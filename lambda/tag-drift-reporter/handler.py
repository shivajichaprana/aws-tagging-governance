"""Untagged-resource drift reporter.

Continuously answers a single governance question: which already-provisioned
resources are missing one or more of the tag keys the organization requires?
The preventive Organizations tag policy constrains values at tag-modification
time and the detective AWS Config rules evaluate individual resources, but
neither produces a single, periodic, human-readable inventory of tag drift.
This function fills that gap.

The scan is strictly read-only. It enumerates resources through the Resource
Groups Tagging API, compares each resource's tags against the required-key set
for its type, and writes two artifacts:

* a date-partitioned JSON report to S3 (server-side encrypted with the
  governance KMS key), suitable for downstream analytics or audit evidence;
* a concise text summary published to an SNS topic for the tagging owners.

It never creates, modifies, or deletes a tag or a resource. Remediation is the
job of a separate, opt-in function.

Scoping mirrors the detective rules: a map of Resource Groups Tagging API
resource-type filter (for example ``ec2:instance`` or ``s3``) to the tag keys
required on that type is supplied through the ``DRIFT_TAG_SCOPES`` environment
variable. When that map is empty the function falls back to scanning the
``RESOURCE_TYPE_FILTERS`` list against the global ``REQUIRED_TAG_KEYS`` set.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3

# --------------------------------------------------------------------------- #
# Configuration and clients
# --------------------------------------------------------------------------- #

_LOGGER = logging.getLogger()
_LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

# Cap how many drifted resources are enumerated inline in the SNS summary so a
# large scan does not exceed the SNS message-size limit. The full detail always
# lives in the S3 report.
_DEFAULT_SUMMARY_LIMIT = 50

# Lazily created boto3 clients, keyed by service name, so unit tests can inject
# fakes and a cold start only pays for the clients it actually uses.
_CLIENTS: Dict[str, Any] = {}


def _client(service: str) -> Any:
    if service not in _CLIENTS:
        _CLIENTS[service] = boto3.client(service)
    return _CLIENTS[service]


def _parse_csv_env(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        _LOGGER.warning("%s is not an integer; using default %d", name, default)
        return default


def _load_scopes() -> Dict[str, List[str]]:
    """Resource-type filter -> required tag keys, from DRIFT_TAG_SCOPES JSON.

    Falls back to scanning RESOURCE_TYPE_FILTERS against the global
    REQUIRED_TAG_KEYS set when no per-type scope map is configured.
    """
    raw = os.environ.get("DRIFT_TAG_SCOPES", "").strip()
    if raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            _LOGGER.warning("DRIFT_TAG_SCOPES is not valid JSON; ignoring it")
            parsed = {}
        if isinstance(parsed, dict) and parsed:
            scopes: Dict[str, List[str]] = {}
            for rtype, keys in parsed.items():
                if isinstance(keys, list):
                    scopes[str(rtype)] = [str(k) for k in keys]
            if scopes:
                return scopes

    required_keys = _parse_csv_env("REQUIRED_TAG_KEYS")
    filters = _parse_csv_env("RESOURCE_TYPE_FILTERS")
    return {f: list(required_keys) for f in filters}


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #

def _iter_resources(resource_type_filter: str):
    """Yield {arn, tags} for every resource of a type, following pagination."""
    client = _client("resourcegroupstaggingapi")
    token = ""
    while True:
        kwargs: Dict[str, Any] = {
            "ResourceTypeFilters": [resource_type_filter],
            "ResourcesPerPage": 100,
        }
        if token:
            kwargs["PaginationToken"] = token
        resp = client.get_resources(**kwargs)
        for mapping in resp.get("ResourceTagMappingList", []):
            tags = {t["Key"]: t["Value"] for t in mapping.get("Tags", [])}
            yield {"arn": mapping.get("ResourceARN", ""), "tags": tags}
        token = resp.get("PaginationToken", "")
        if not token:
            return


def _evaluate_type(
    resource_type_filter: str,
    required_keys: List[str],
    exclusion_keys: List[str],
) -> Dict[str, Any]:
    """Scan one resource type and classify each resource as compliant,
    excluded, or drifted (missing at least one required key)."""
    scanned = 0
    excluded = 0
    compliant = 0
    drifted: List[Dict[str, Any]] = []

    try:
        for resource in _iter_resources(resource_type_filter):
            scanned += 1
            tags = resource["tags"]

            if any(key in tags for key in exclusion_keys):
                excluded += 1
                continue

            missing = [key for key in required_keys if key not in tags]
            if missing:
                drifted.append(
                    {
                        "arn": resource["arn"],
                        "resource_type": resource_type_filter,
                        "missing_tag_keys": missing,
                        "present_tag_keys": sorted(tags.keys()),
                    }
                )
            else:
                compliant += 1
    except Exception:  # noqa: BLE001 - one resource type must not sink the scan
        _LOGGER.exception("Failed while scanning resource type %s", resource_type_filter)

    return {
        "scanned": scanned,
        "compliant": compliant,
        "excluded": excluded,
        "drifted": len(drifted),
        "drifted_resources": drifted,
    }


# --------------------------------------------------------------------------- #
# Report delivery
# --------------------------------------------------------------------------- #

def _write_report(report: Dict[str, Any]) -> Optional[str]:
    bucket = os.environ.get("REPORT_BUCKET")
    if not bucket:
        _LOGGER.info("REPORT_BUCKET is not set; skipping S3 report")
        return None

    prefix = os.environ.get("REPORT_PREFIX", "tag-drift").strip("/")
    generated = report["generated_at"]
    date_part = generated[:10]
    stamp = generated.replace(":", "").replace("-", "")
    key = f"{prefix}/date={date_part}/tag-drift-{stamp}.json"

    _client("s3").put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(report, indent=2, default=str).encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="aws:kms",
    )
    location = f"s3://{bucket}/{key}"
    _LOGGER.info("Wrote drift report to %s", location)
    return location


def _publish_summary(
    report: Dict[str, Any], report_location: Optional[str], summary_limit: int
) -> None:
    topic_arn = os.environ.get("SNS_TOPIC_ARN") or None
    if not topic_arn:
        _LOGGER.info("SNS_TOPIC_ARN is not set; skipping notification")
        return

    summary = report["summary"]
    lines = [
        "Tag drift report",
        f"Account: {report['account_id']}  Region: {report['region']}",
        f"Generated: {report['generated_at']}",
        "",
        f"Resources scanned:  {summary['scanned']}",
        f"Compliant:          {summary['compliant']}",
        f"Drifted:            {summary['drifted']}",
        f"Excluded (opt-out): {summary['excluded']}",
        "",
        "By resource type:",
    ]
    for rtype, counts in sorted(report["by_resource_type"].items()):
        lines.append(
            f"  {rtype}: {counts['drifted']} drifted / {counts['scanned']} scanned"
        )

    drifted_resources = report["drifted_resources"]
    if drifted_resources:
        lines.append("")
        lines.append(f"Top {min(summary_limit, len(drifted_resources))} drifted resources:")
        for item in drifted_resources[:summary_limit]:
            lines.append(f"  {item['arn']} — missing {', '.join(item['missing_tag_keys'])}")
        if len(drifted_resources) > summary_limit:
            lines.append(f"  … and {len(drifted_resources) - summary_limit} more")

    if report_location:
        lines.append("")
        lines.append(f"Full report: {report_location}")

    _client("sns").publish(
        TopicArn=topic_arn,
        Subject=f"Tag drift report — {summary['drifted']} drifted resource(s)",
        Message="\n".join(lines),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    _LOGGER.info("Drift report invoked")

    account_id = os.environ.get("ACCOUNT_ID", "")
    region = os.environ.get("AWS_REGION", "us-east-1")
    exclusion_keys = _parse_csv_env("EXCLUSION_TAG_KEYS") or ["tagging:no-remediate"]
    summary_limit = _int_env("MAX_DRIFTED_IN_SUMMARY", _DEFAULT_SUMMARY_LIMIT)
    scopes = _load_scopes()

    generated_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    by_resource_type: Dict[str, Dict[str, int]] = {}
    drifted_resources: List[Dict[str, Any]] = []
    totals = {"scanned": 0, "compliant": 0, "excluded": 0, "drifted": 0}

    for resource_type_filter, required_keys in scopes.items():
        if not required_keys:
            _LOGGER.warning(
                "No required keys configured for %s; skipping", resource_type_filter
            )
            continue

        result = _evaluate_type(resource_type_filter, required_keys, exclusion_keys)
        by_resource_type[resource_type_filter] = {
            "scanned": result["scanned"],
            "compliant": result["compliant"],
            "excluded": result["excluded"],
            "drifted": result["drifted"],
        }
        drifted_resources.extend(result["drifted_resources"])
        totals["scanned"] += result["scanned"]
        totals["compliant"] += result["compliant"]
        totals["excluded"] += result["excluded"]
        totals["drifted"] += result["drifted"]

    # Surface the worst offenders first (most missing keys), then by ARN.
    drifted_resources.sort(key=lambda r: (-len(r["missing_tag_keys"]), r["arn"]))

    report = {
        "generated_at": generated_at,
        "account_id": account_id,
        "region": region,
        "summary": totals,
        "by_resource_type": by_resource_type,
        "drifted_resources": drifted_resources,
    }

    report_location = _write_report(report)
    _publish_summary(report, report_location, summary_limit)

    return {
        "scanned": totals["scanned"],
        "drifted": totals["drifted"],
        "compliant": totals["compliant"],
        "excluded": totals["excluded"],
        "report_location": report_location,
    }
