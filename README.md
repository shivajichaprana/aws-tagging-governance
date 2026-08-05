# aws-tagging-governance

Tag governance for AWS: standardize the tags every resource must carry, detect
resources that fall out of compliance, remediate them automatically, and report
on drift. The controls layer together — a preventive organization-wide tag
policy on top, detective AWS Config rules underneath, and an automated
remediation and reporting workflow closing the loop.

## Capabilities

| Layer | Control | Purpose |
|-------|---------|---------|
| Prevent | Organizations tag policy | Standardize required tag keys, allowed values, and the resource types a non-compliant value is blocked on |
| Detect | AWS Config required-tags rules | Continuously evaluate resources against the tagging standard |
| Remediate | Tag remediation automation | Apply default tags to non-compliant resources and notify owners |
| Report | Drift reporter | Summarize untagged and mis-tagged resources and deliver the report |

This repository ships all four layers: the preventive Organizations tag
policy, the detective AWS Config required-tags rules, the remediation
automation that applies default tags to non-compliant resources, and the
reporting layer that periodically inventories tag drift and delivers the
findings.

## Repository layout

| Path | Description |
|------|-------------|
| `versions.tf` | Terraform and provider version constraints |
| `providers.tf` | AWS provider and organization-wide default tags |
| `variables.tf` | Input variables, including the declarative tagging standard |
| `tag-policies.tf` | Organizations tag policy document and attachments |
| `config-rules.tf` | AWS Config required-tags rules with per-resource scoping and an optional recorder |
| `remediation.tf` | Remediation function, notification topic, SSM Automation document, and Config remediation wiring |
| `reporting.tf` | Drift reporter function, report bucket, notification topic, and schedule |
| `lambda/tag-remediator/` | Function that applies default tags to non-compliant resources |
| `lambda/tag-drift-reporter/` | Read-only function that reports resources missing required tags |
| `ssm/tag-remediation.yaml` | SSM Automation document that invokes the remediation function |
| `outputs.tf` | Policy ID/ARN, rendered document, attachment targets, and Config rule names/ARNs |

## The tagging standard

The required tags are declared as data in `variables.tf`. Each entry maps a tag
key to its allowed values and the resource types the value is enforced on:

```hcl
required_tags = {
  Environment = {
    allowed_values = ["production", "staging", "development", "sandbox"]
    enforced_for   = ["ec2:instance", "ec2:volume", "s3:bucket", "rds:db"]
  }
  Owner      = {}                       # required key, free-form value
  CostCenter = { enforced_for = ["ec2:instance", "rds:db"] }
}
```

- An empty `allowed_values` list means the key is required but its value is free
  form.
- An empty `enforced_for` list means non-compliant values are reported (by the
  detective layer) but not blocked at tag-modification time.

The configuration turns this into the AWS tag-policy schema automatically, so
adding a new standard tag is a one-line change.

## Quick start

Organizations tag policies are managed from the management account or a
delegated administrator for the Organizations policy service. Point the provider
at that account, then:

```bash
terraform init
terraform plan

# Review the rendered policy before attaching it anywhere:
terraform output -raw tag_policy_document | jq

# Attach to an organization root, OU, or account by setting policy_target_ids,
# then apply. Use real IDs in your own environment; the examples below are
# placeholders.
terraform apply -var 'policy_target_ids=["r-abcd"]'
```

Example values in this repository use placeholders only — organization root
`r-abcd`, OU `ou-abcd-11111111`, and account ID `123456789012`. Replace them
with your own before applying.

## Detective layer — AWS Config

`config-rules.tf` creates one AWS Config `REQUIRED_TAGS` rule per resource type,
so each type is evaluated against its own required-key set. The mapping lives in
the `config_rule_resource_scopes` variable, and the allowed values for each key
are sourced from the same `required_tags` definition the tag policy uses:

```hcl
config_rule_resource_scopes = {
  "AWS::EC2::Instance"   = ["Environment", "Owner", "CostCenter"]
  "AWS::S3::Bucket"      = ["Environment", "Owner", "DataClassification"]
  "AWS::DynamoDB::Table" = ["Environment", "Owner", "DataClassification"]
}
```

Each rule is scoped to a single resource type via `compliance_resource_types`
and packs up to six keys into the managed rule's input schema. The rules assume
a configuration recorder is already active in the account (the common case when
Config is enabled centrally); set `create_config_recorder = true` to provision a
recorder, delivery channel, and hardened delivery bucket for a standalone
account.

## Remediation layer

`remediation.tf` provisions an automated workflow that fills in the
organization's default tag values on resources the detective layer flags as
non-compliant, and publishes a summary of the actions taken.

The remediation is deliberately conservative:

- It sets only the *missing* required tag keys that have a safe default in
  `default_tag_values`. A key whose value cannot be safely guessed (for example
  `Environment`) is intentionally omitted so the workflow never writes a value
  that would itself be non-compliant.
- It never overwrites an existing tag value.
- It skips any resource carrying one of the `remediation_exclusion_tag_keys`,
  giving owners a documented opt-out.
- `remediation_dry_run` runs the whole flow in report-only mode.

Actuation is opt-in. The function, notification topic, and SSM Automation
document are created by default, but the two triggers stay off until you choose
to enable them:

```hcl
# Invoke the function the moment AWS Config reports a resource non-compliant.
enable_event_driven_remediation = true

# Wire each required-tags rule to the SSM document as a Config remediation.
enable_config_remediation    = true
config_remediation_automatic = true
```

Until then, the SSM Automation document can be run on demand against a single
resource, making it easy to validate the behavior before enabling it fleet-wide.

## Reporting layer

`reporting.tf` provisions a scheduled, read-only inventory of tag drift. Where
the detective rules evaluate resources one at a time, the reporter produces the
single periodic answer to "what is currently untagged?" that owners act on.

On each run the function enumerates resources through the Resource Groups
Tagging API, compares each against the required-key set for its type, and:

- writes a date-partitioned JSON report to an encrypted S3 bucket (suitable for
  audit evidence or downstream analytics);
- publishes a text summary to a dedicated SNS topic, worst offenders first.

Scoping mirrors the detective layer via `drift_resource_type_scopes`, which maps
each Resource Groups Tagging API resource-type filter to the keys required on
it:

```hcl
drift_resource_type_scopes = {
  "ec2:instance"   = ["Environment", "Owner", "CostCenter"]
  "s3:bucket"      = ["Environment", "Owner", "DataClassification"]
  "dynamodb:table" = ["Environment", "Owner", "DataClassification"]
}
```

The scan writes nothing back to any resource and honours the same opt-out tag
keys as the remediation layer. It is self-contained — its own key, bucket, and
topic — so it can be enabled independently, and runs on the schedule set by
`drift_report_schedule_expression` (weekly by default).

## Design principles

- **Standard as data.** The tagging standard is a single declarative variable,
  not hand-written policy JSON, so it is easy to review and extend.
- **Review before enforce.** With no attachment targets the policy is created
  but inert, letting you inspect the rendered document before it takes effect.
- **Layered controls.** Prevention (tag policy), detection (Config),
  remediation, and reporting are separate, composable layers rather than a
  single mechanism.
- **Report, never mutate.** The drift reporter only reads and summarizes;
  changing a resource's tags is the remediation layer's job alone.

## License

Released under the MIT License. See [LICENSE](LICENSE).
