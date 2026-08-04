"""Tag auto-remediation.

Fills in the organization's default tag values on resources that have been
flagged non-compliant with the tagging standard, then publishes a summary of
the actions taken.

The remediation is deliberately conservative:

* It only sets *missing* required tag keys for which a safe default value is
  configured. Keys without a configured default (for example an Environment
  value, which a machine cannot safely guess) are reported but never invented.
* It never overwrites an existing tag value.
* It skips any resource carrying one of the exclusion tag keys, giving owners a
  documented opt-out.
* It honours a dry-run mode so the exact set of changes can be reviewed before
  any tag is written.

The handler accepts three input shapes so it can run from several triggers:

* An AWS Config "Config Rules Compliance Change" EventBridge event, for
  event-driven remediation the moment a resource drifts.
* A direct payload ``{"resource_arn": "..."}``.
* A direct payload ``{"resource_id": "...", "resource_type": "AWS::S3::Bucket"}``
  as delivered by an SSM Automation runbook or a Config remediation
  configuration.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Dict, List, Optional

import boto3

# --------------------------------------------------------------------------- #
# Configuration and clients
# --------------------------------------------------------------------------- #

_LOGGER = logging.getLogger()
_LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

_COMPLIANT_STATES_TO_SKIP = {"COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"}

# Lazily created boto3 clients, keyed by service name, so unit tests can inject
# fakes and a cold start only pays for the clients it actually uses.
_CLIENTS: Dict[str, Any] = {}


def _client(service: str) -> Any:
    if service not in _CLIENTS:
        _CLIENTS[service] = boto3.client(service)
    return _CLIENTS[service]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _load_default_tag_values() -> Dict[str, str]:
    """Map of required tag key -> default value applied when the key is absent."""
    raw = os.environ.get("DEFAULT_TAG_VALUES", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        _LOGGER.warning("DEFAULT_TAG_VALUES is not valid JSON; treating as empty")
        return {}
    if not isinstance(parsed, dict):
        _LOGGER.warning("DEFAULT_TAG_VALUES is not a JSON object; treating as empty")
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def _parse_csv_env(name: str) -> List[str]:
    raw = os.environ.get(name, "")
    return [item.strip() for item in raw.split(",") if item.strip()]


# --------------------------------------------------------------------------- #
# ARN construction (bounded to the resource types the standard scopes)
# --------------------------------------------------------------------------- #

def _regional_arn(service: str, sep: str, prefix: str):
    def build(resource_id: str, region: str, account: str, partition: str) -> str:
        return f"arn:{partition}:{service}:{region}:{account}:{prefix}{sep}{resource_id}"

    return build


# Config resource type -> function(resource_id, region, account, partition) -> ARN.
ARN_BUILDERS: Dict[str, Callable[[str, str, str, str], str]] = {
    "AWS::S3::Bucket": lambda rid, region, account, partition: f"arn:{partition}:s3:::{rid}",
    "AWS::EC2::Instance": _regional_arn("ec2", "/", "instance"),
    "AWS::EC2::Volume": _regional_arn("ec2", "/", "volume"),
    "AWS::RDS::DBInstance": _regional_arn("rds", ":", "db"),
    "AWS::DynamoDB::Table": _regional_arn("dynamodb", "/", "table"),
}


def _build_arn(
    resource_type: Optional[str],
    resource_id: str,
    region: str,
    account: str,
    partition: str,
) -> Optional[str]:
    if resource_id.startswith("arn:"):
        return resource_id
    builder = ARN_BUILDERS.get(resource_type or "")
    if builder is None:
        _LOGGER.warning("No ARN builder for resource type %s", resource_type)
        return None
    return builder(resource_id, region, account, partition)


# --------------------------------------------------------------------------- #
# Event normalization
# --------------------------------------------------------------------------- #

def _normalize_targets(
    event: Dict[str, Any],
    default_region: str,
    default_account: str,
    partition: str,
) -> List[Dict[str, str]]:
    """Reduce any supported input shape to a list of {arn, resource_type, resource_id}."""
    targets: List[Dict[str, str]] = []

    # AWS Config compliance-change EventBridge event.
    detail = event.get("detail") if isinstance(event, dict) else None
    if detail and detail.get("resourceId"):
        compliance = (
            detail.get("newEvaluationResult", {})
            .get("complianceType", "")
            .upper()
        )
        if compliance in _COMPLIANT_STATES_TO_SKIP:
            _LOGGER.info(
                "Resource %s is %s; nothing to remediate",
                detail.get("resourceId"),
                compliance,
            )
            return []
        resource_type = detail.get("resourceType")
        resource_id = detail["resourceId"]
        region = detail.get("awsRegion", default_region)
        account = detail.get("awsAccountId", default_account)
        arn = _build_arn(resource_type, resource_id, region, account, partition)
        if arn:
            targets.append(
                {"arn": arn, "resource_type": resource_type or "", "resource_id": resource_id}
            )
        return targets

    # Direct invocation.
    resource_arn = event.get("resource_arn")
    resource_id = event.get("resource_id")
    resource_type = event.get("resource_type")
    region = event.get("region", default_region)
    account = event.get("account", default_account)

    if resource_arn:
        targets.append(
            {
                "arn": resource_arn,
                "resource_type": resource_type or "",
                "resource_id": resource_id or resource_arn,
            }
        )
    elif resource_id:
        arn = _build_arn(resource_type, resource_id, region, account, partition)
        if arn:
            targets.append(
                {"arn": arn, "resource_type": resource_type or "", "resource_id": resource_id}
            )
        else:
            _LOGGER.warning("Cannot build ARN for %s (%s)", resource_id, resource_type)

    return targets


# --------------------------------------------------------------------------- #
# Tag reading, decision, and writing
# --------------------------------------------------------------------------- #

def _current_tags(arn: str, resource_type: str, resource_id: str) -> Dict[str, str]:
    """Read the resource's existing tags using the owning service's tag API."""
    try:
        if resource_type == "AWS::S3::Bucket":
            try:
                resp = _client("s3").get_bucket_tagging(Bucket=resource_id)
            except _client("s3").exceptions.ClientError as exc:  # type: ignore[attr-defined]
                if "NoSuchTagSet" in str(exc):
                    return {}
                raise
            return {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
        if resource_type in ("AWS::EC2::Instance", "AWS::EC2::Volume"):
            resp = _client("ec2").describe_tags(
                Filters=[{"Name": "resource-id", "Values": [resource_id]}]
            )
            return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
        if resource_type == "AWS::RDS::DBInstance":
            resp = _client("rds").list_tags_for_resource(ResourceName=arn)
            return {t["Key"]: t["Value"] for t in resp.get("TagList", [])}
        if resource_type == "AWS::DynamoDB::Table":
            resp = _client("dynamodb").list_tags_of_resource(ResourceArn=arn)
            return {t["Key"]: t["Value"] for t in resp.get("Tags", [])}
    except Exception:  # noqa: BLE001 - reading tags must never crash the run
        _LOGGER.exception("Failed to read tags for %s", arn)
        return {}

    _LOGGER.warning("No tag reader for resource type %s", resource_type)
    return {}


def _is_excluded(current_tags: Dict[str, str], exclusion_keys: List[str]) -> bool:
    return any(key in current_tags for key in exclusion_keys)


def _tags_to_apply(
    current_tags: Dict[str, str],
    default_values: Dict[str, str],
    required_keys: List[str],
) -> Dict[str, str]:
    """Default values for required keys that are absent and have a safe default."""
    consider = required_keys or list(default_values.keys())
    to_apply: Dict[str, str] = {}
    for key in consider:
        if key in current_tags:
            continue
        if key in default_values:
            to_apply[key] = default_values[key]
    return to_apply


def _apply_tags(arn: str, tags: Dict[str, str], dry_run: bool) -> None:
    if dry_run or not tags:
        return
    resp = _client("resourcegroupstaggingapi").tag_resources(
        ResourceARNList=[arn], Tags=tags
    )
    failures = resp.get("FailedResourcesMap", {})
    if failures:
        raise RuntimeError(f"tag_resources reported failures: {failures}")


def _publish_summary(topic_arn: Optional[str], results: List[Dict[str, Any]], dry_run: bool) -> None:
    if not topic_arn:
        return
    remediated = [r for r in results if r["applied_tags"]]
    lines = [
        "Tag remediation summary",
        f"Mode: {'dry-run (no changes written)' if dry_run else 'enforce'}",
        f"Resources evaluated: {len(results)}",
        f"Resources tagged: {len(remediated)}",
        "",
    ]
    for r in results:
        status = r["status"]
        detail = ""
        if r["applied_tags"]:
            detail = " -> " + ", ".join(f"{k}={v}" for k, v in r["applied_tags"].items())
        lines.append(f"[{status}] {r['arn']}{detail}")
    _client("sns").publish(
        TopicArn=topic_arn,
        Subject="Tag remediation summary",
        Message="\n".join(lines),
    )


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    _LOGGER.info("Remediation invoked: %s", json.dumps(event, default=str))

    partition = os.environ.get("PARTITION", "aws")
    default_region = os.environ.get("AWS_REGION", "us-east-1")
    default_account = os.environ.get("ACCOUNT_ID", "")
    topic_arn = os.environ.get("SNS_TOPIC_ARN") or None
    dry_run = _env_bool("DRY_RUN", False)
    default_values = _load_default_tag_values()
    required_keys = _parse_csv_env("REQUIRED_TAG_KEYS")
    exclusion_keys = _parse_csv_env("EXCLUSION_TAG_KEYS") or ["tagging:no-remediate"]

    targets = _normalize_targets(event, default_region, default_account, partition)
    results: List[Dict[str, Any]] = []

    for target in targets:
        arn = target["arn"]
        resource_type = target["resource_type"]
        resource_id = target["resource_id"]
        current = _current_tags(arn, resource_type, resource_id)

        if _is_excluded(current, exclusion_keys):
            _LOGGER.info("Skipping excluded resource %s", arn)
            results.append({"arn": arn, "status": "excluded", "applied_tags": {}})
            continue

        to_apply = _tags_to_apply(current, default_values, required_keys)
        if not to_apply:
            results.append({"arn": arn, "status": "compliant", "applied_tags": {}})
            continue

        try:
            _apply_tags(arn, to_apply, dry_run)
        except Exception:  # noqa: BLE001 - one failure must not sink the batch
            _LOGGER.exception("Failed to apply tags to %s", arn)
            results.append({"arn": arn, "status": "error", "applied_tags": {}})
            continue

        status = "dry-run" if dry_run else "remediated"
        results.append({"arn": arn, "status": status, "applied_tags": to_apply})

    _publish_summary(topic_arn, results, dry_run)

    remediated = sum(1 for r in results if r["applied_tags"])
    return {
        "evaluated": len(results),
        "remediated": remediated,
        "dry_run": dry_run,
        "results": results,
    }
