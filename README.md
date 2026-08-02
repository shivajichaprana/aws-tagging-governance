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

This repository currently ships the preventive layer (the Organizations tag
policy); the detective, remediation, and reporting layers are added as the
platform grows.

## Repository layout

| Path | Description |
|------|-------------|
| `versions.tf` | Terraform and provider version constraints |
| `providers.tf` | AWS provider and organization-wide default tags |
| `variables.tf` | Input variables, including the declarative tagging standard |
| `tag-policies.tf` | Organizations tag policy document and attachments |
| `outputs.tf` | Policy ID/ARN, rendered document, and attachment targets |

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

## Design principles

- **Standard as data.** The tagging standard is a single declarative variable,
  not hand-written policy JSON, so it is easy to review and extend.
- **Review before enforce.** With no attachment targets the policy is created
  but inert, letting you inspect the rendered document before it takes effect.
- **Layered controls.** Prevention (tag policy), detection (Config), and
  remediation are separate, composable layers rather than a single mechanism.

## License

Released under the MIT License. See [LICENSE](LICENSE).
