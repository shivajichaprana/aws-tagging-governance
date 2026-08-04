# tag-remediator

Applies the organization's default tag values to resources flagged
non-compliant with the tagging standard, then publishes a summary of the
actions taken.

## Behavior

- Sets only the *missing* required tag keys that have a safe default configured
  in `DEFAULT_TAG_VALUES`. Keys without a default (for example `Environment`,
  whose value cannot be safely guessed) are reported but never invented.
- Never overwrites an existing tag value.
- Skips any resource carrying one of the `EXCLUSION_TAG_KEYS`, giving owners a
  documented opt-out.
- Honours `DRY_RUN` so the exact set of changes can be reviewed before any tag
  is written.

## Input shapes

| Trigger | Payload |
|---------|---------|
| AWS Config compliance change | The native `Config Rules Compliance Change` EventBridge event |
| SSM Automation / Config remediation | `{"resource_id": "...", "resource_type": "AWS::S3::Bucket"}` |
| Direct call | `{"resource_arn": "arn:aws:s3:::example"}` |

## Environment variables

| Variable | Purpose |
|----------|---------|
| `DEFAULT_TAG_VALUES` | JSON map of tag key to the default value applied when the key is missing |
| `REQUIRED_TAG_KEYS` | Comma-separated required keys to consider (defaults to the keys in `DEFAULT_TAG_VALUES`) |
| `EXCLUSION_TAG_KEYS` | Comma-separated opt-out tag keys (default `tagging:no-remediate`) |
| `DRY_RUN` | When true, evaluate and report without writing tags |
| `SNS_TOPIC_ARN` | Topic for the remediation summary (optional) |
| `PARTITION` / `ACCOUNT_ID` | Used to build ARNs for direct resource-id invocations |
| `LOG_LEVEL` | Logger level (default `INFO`) |

## Supported resource types

EC2 instances and volumes, S3 buckets, RDS DB instances, and DynamoDB tables —
the resource types the tagging standard scopes. Extend `ARN_BUILDERS` and the
tag-reader dispatch to cover additional types.
