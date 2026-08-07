# Tagging standard

This is the reference for the organization's required tags. The standard is
declared once, as data, in the `required_tags` variable, and every governance
layer — the preventive tag policy, the detective Config rules, the remediation
defaults, and the drift reporter — derives its behavior from it.

## Required tag keys

| Key | Allowed values | Value form | Purpose |
|-----|----------------|-----------|---------|
| `Environment` | `production`, `staging`, `development`, `sandbox` | Constrained | Which lifecycle stage the resource belongs to |
| `Owner` | any | Free form | The team or individual accountable for the resource |
| `CostCenter` | any | Free form | The cost center the resource's spend is attributed to |
| `Project` | any | Free form | The project or initiative the resource supports |
| `DataClassification` | `public`, `internal`, `confidential`, `restricted` | Constrained | The sensitivity of the data the resource handles |

A key with an empty allowed-values list is required but its value is free form.
A key with a constrained value list rejects any value outside the list on the
resource types it is enforced for.

## Enforcement matrix

`enforced_for` controls where a *non-compliant value* is blocked at
tag-modification time by the Organizations tag policy. A key that is required but
not enforced for a given type is still evaluated by the detective and reporting
layers — it is simply not blocked at write time.

| Key | Enforced for |
|-----|--------------|
| `Environment` | `ec2:instance`, `ec2:volume`, `s3:bucket`, `rds:db` |
| `Owner` | (reported only) |
| `CostCenter` | `ec2:instance`, `rds:db` |
| `Project` | (reported only) |
| `DataClassification` | `s3:bucket`, `dynamodb:table` |

## Detection scope

The detective AWS Config rules evaluate a required-key subset per resource type,
declared in `config_rule_resource_scopes`. The `REQUIRED_TAGS` managed rule
supports at most six keys per resource type.

| AWS Config resource type | Required keys |
|--------------------------|---------------|
| `AWS::EC2::Instance` | `Environment`, `Owner`, `CostCenter` |
| `AWS::EC2::Volume` | `Environment`, `Owner` |
| `AWS::S3::Bucket` | `Environment`, `Owner`, `DataClassification` |
| `AWS::RDS::DBInstance` | `Environment`, `Owner`, `CostCenter` |
| `AWS::DynamoDB::Table` | `Environment`, `Owner`, `DataClassification` |

## Drift scope

The drift reporter scans resources through the Resource Groups Tagging API,
using its own resource-type filter map, `drift_resource_type_scopes`, mirroring
the detection scope with tagging-API type identifiers.

| Tagging API resource type | Required keys |
|---------------------------|---------------|
| `ec2:instance` | `Environment`, `Owner`, `CostCenter` |
| `ec2:volume` | `Environment`, `Owner` |
| `s3:bucket` | `Environment`, `Owner`, `DataClassification` |
| `rds:db` | `Environment`, `Owner`, `CostCenter` |
| `dynamodb:table` | `Environment`, `Owner`, `DataClassification` |

## Remediation defaults

Only the keys below carry a safe default, so only these are ever auto-applied to
a missing key. `Environment` is deliberately excluded: its correct value cannot
be inferred, and writing a placeholder would itself be non-compliant. Existing
tag values are never overwritten.

| Key | Default value applied when missing |
|-----|------------------------------------|
| `Owner` | `unassigned` |
| `CostCenter` | `unallocated` |
| `Project` | `untracked` |
| `DataClassification` | `internal` |

## Extending the standard

Adding or changing a standard tag is a single-variable change that flows through
every layer:

1. Add the key to `required_tags` with its `allowed_values` and `enforced_for`.
2. Reference the key in `config_rule_resource_scopes` for the resource types you
   want detected (respecting the six-key limit per type).
3. Add it to `drift_resource_type_scopes` for the types you want reported.
4. If the key has a safe default, add it to `default_tag_values`; if its value
   cannot be safely guessed, leave it out so remediation reports rather than
   invents a value.
5. Run `make validate`, review `terraform plan`, and roll out per the
   [runbook](runbook.md).

## Opt-out

A resource carrying any key in `remediation_exclusion_tag_keys` (default
`tagging:no-remediate`) is skipped by both the remediation function and the
drift reporter. Use it sparingly and document why, so exceptions stay visible.
