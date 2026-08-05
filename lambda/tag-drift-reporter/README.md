# tag-drift-reporter

A read-only Lambda that reports tag drift: it inventories resources that are
missing one or more of the tag keys the organization requires and delivers the
findings as an S3 report plus an SNS summary.

## What it does

1. Loads a per-resource-type scope map (Resource Groups Tagging API resource
   type filter → required tag keys).
2. Enumerates every resource of each type via the Resource Groups Tagging API,
   following pagination.
3. Classifies each resource:
   - **excluded** — carries an opt-out tag key, skipped;
   - **compliant** — all required keys present;
   - **drifted** — one or more required keys missing.
4. Writes a date-partitioned JSON report to S3 (encrypted with the governance
   KMS key) and publishes a text summary to SNS, worst offenders first.

The function performs only describe/list reads plus a single `PutObject` to its
own report bucket and an SNS `Publish`. It never writes a tag or mutates a
resource — remediation is handled by a separate, opt-in function.

## Configuration (environment variables)

| Variable | Description |
| --- | --- |
| `DRIFT_TAG_SCOPES` | JSON map of resource-type filter → required tag keys. |
| `REQUIRED_TAG_KEYS` | Comma-separated fallback keys when no scope map is set. |
| `RESOURCE_TYPE_FILTERS` | Comma-separated fallback resource-type filters. |
| `EXCLUSION_TAG_KEYS` | Comma-separated opt-out tag keys. |
| `REPORT_BUCKET` | Bucket the JSON report is written to. |
| `REPORT_PREFIX` | Key prefix for reports (default `tag-drift`). |
| `SNS_TOPIC_ARN` | Topic the summary is published to. |
| `MAX_DRIFTED_IN_SUMMARY` | Max drifted resources listed inline in the summary. |
| `ACCOUNT_ID` | Account id recorded in the report header. |
| `LOG_LEVEL` | Log level (default `INFO`). |

## Report shape

```json
{
  "generated_at": "2020-01-01T00:00:00Z",
  "account_id": "123456789012",
  "region": "us-east-1",
  "summary": { "scanned": 0, "compliant": 0, "excluded": 0, "drifted": 0 },
  "by_resource_type": { "ec2:instance": { "scanned": 0, "compliant": 0, "excluded": 0, "drifted": 0 } },
  "drifted_resources": [
    { "arn": "…", "resource_type": "ec2:instance", "missing_tag_keys": ["Owner"], "present_tag_keys": ["Environment"] }
  ]
}
```
