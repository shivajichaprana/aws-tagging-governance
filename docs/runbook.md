# Operator runbook

Procedures for rolling out and operating tag governance. All examples use
placeholder identifiers — organization root `r-abcd`, OU `ou-abcd-11111111`, and
account ID `123456789012`. Substitute your own.

## Prerequisites

- Terraform and (for policy attachment) credentials for the management account
  or a delegated administrator for the Organizations policy service.
- An active AWS Config configuration recorder in each target account, or
  `create_config_recorder = true` for standalone accounts.
- `jq` for inspecting the rendered policy document (optional).

## Review-first rollout

The policy is created inert when `policy_target_ids` is empty, so you can review
the rendered document before it affects any account.

1. Validate and plan:

   ```bash
   make validate
   make plan
   ```

2. Inspect the rendered tag policy:

   ```bash
   terraform output -raw tag_policy_document | jq
   ```

3. Attach to a low-risk scope first (a sandbox OU or single account), confirm no
   legitimate tag writes are blocked, then widen the attachment:

   ```bash
   terraform apply -var 'policy_target_ids=["ou-abcd-11111111"]'
   ```

## Detective layer

With `enable_config_rules = true` (the default), one `REQUIRED_TAGS` rule per
resource type evaluates existing resources. Review current compliance:

```bash
# List the rule names this configuration created.
terraform output config_rule_names

# Inspect compliance for one rule.
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <rule-name> \
  --compliance-types NON_COMPLIANT
```

If rules report `INSUFFICIENT_DATA`, confirm a configuration recorder is active
in the account.

## Remediation procedures

Remediation is provisioned by default but does not act until you enable a
trigger. Roll it out in stages.

### Stage 1 — validate on demand (dry run)

Run the SSM Automation document against a single known-non-compliant resource
with the function in report-only mode (`remediation_dry_run = true`) and confirm
the summary describes the changes it *would* make without writing tags.

```bash
terraform output ssm_remediation_document_name

aws ssm start-automation-execution \
  --document-name <document-name> \
  --parameters 'ResourceId=<id>,ResourceType=AWS::S3::Bucket'
```

### Stage 2 — enable actuation

Once validated, turn `remediation_dry_run` off and enable one trigger:

```hcl
# Invoke the function when AWS Config reports a resource non-compliant.
enable_event_driven_remediation = true

# Or wire each Config rule to the SSM document as native Config remediation.
enable_config_remediation    = true
config_remediation_automatic = true
```

Remediation only fills *missing* required keys that have a safe default (see the
[tagging standard](tagging-standard.md#remediation-defaults)); it never
overwrites an existing value and never invents a value for a key without a safe
default. Notifications are published to the remediation SNS topic — subscribe via
`notification_email_addresses`.

### Opt-out

To exempt a resource, tag it with an opt-out key
(`remediation_exclusion_tag_keys`, default `tagging:no-remediate`). Both the
remediation function and the drift reporter skip it. Record the reason so
exceptions remain visible.

## Drift report triage

The drift reporter runs on `drift_report_schedule_expression` (weekly by
default) and can be invoked on demand:

```bash
terraform output tag_drift_reporter_function_name

aws lambda invoke \
  --function-name <function-name> \
  /dev/stdout
```

Each run:

- writes a date-partitioned JSON report to the drift report bucket
  (`terraform output drift_report_bucket`), suitable for audit evidence or
  downstream analytics; and
- publishes a worst-offenders-first summary to the drift SNS topic
  (`terraform output drift_topic_arn`) — subscribe via
  `drift_report_email_addresses`.

Work the summary top-down: the resources missing the most required keys appear
first. For each, either apply the correct tags (or let remediation apply the
safe defaults) or, if it is a legitimate exception, apply the opt-out tag and
document it.

## Routine cadence

| Cadence | Action |
|---------|--------|
| On alert | Triage a remediation or drift notification as it arrives |
| Weekly | Review the drift report; drive the worst offenders to zero |
| On change | When the standard changes, run `make validate`, plan, and re-attach |
| Periodic | Re-check the opt-out list and remove stale exemptions |

## Teardown

```bash
make destroy
```

Detaching the tag policy (by emptying `policy_target_ids` and applying) stops
enforcement without deleting the rest of the governance stack, which is often
preferable to a full destroy.
