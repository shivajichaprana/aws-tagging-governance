"""Unit tests for the untagged-resource drift reporter."""

from __future__ import annotations

import json

import pytest

from fakes import FakeResourceGroupsTaggingAPI, FakeS3, RecordingSNS

pytestmark = pytest.mark.usefixtures("clear_tag_env", "reset_clients")

_SCOPES = {
    "s3": ["Environment", "Owner", "DataClassification"],
    "ec2:instance": ["Environment", "Owner"],
}


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def test_parse_csv_env(drift_reporter, monkeypatch):
    monkeypatch.setenv("REQUIRED_TAG_KEYS", "Environment, Owner ,,Team")
    assert drift_reporter._parse_csv_env("REQUIRED_TAG_KEYS") == ["Environment", "Owner", "Team"]


def test_int_env_valid_and_fallback(drift_reporter, monkeypatch):
    monkeypatch.setenv("MAX_DRIFTED_IN_SUMMARY", "25")
    assert drift_reporter._int_env("MAX_DRIFTED_IN_SUMMARY", 50) == 25
    monkeypatch.setenv("MAX_DRIFTED_IN_SUMMARY", "not-a-number")
    assert drift_reporter._int_env("MAX_DRIFTED_IN_SUMMARY", 50) == 50
    monkeypatch.delenv("MAX_DRIFTED_IN_SUMMARY", raising=False)
    assert drift_reporter._int_env("MAX_DRIFTED_IN_SUMMARY", 50) == 50


def test_load_scopes_from_json(drift_reporter, monkeypatch):
    monkeypatch.setenv("DRIFT_TAG_SCOPES", json.dumps(_SCOPES))
    assert drift_reporter._load_scopes() == _SCOPES


def test_load_scopes_fallback_to_filters(drift_reporter, monkeypatch):
    monkeypatch.delenv("DRIFT_TAG_SCOPES", raising=False)
    monkeypatch.setenv("REQUIRED_TAG_KEYS", "Environment,Owner")
    monkeypatch.setenv("RESOURCE_TYPE_FILTERS", "s3,ec2:instance")
    scopes = drift_reporter._load_scopes()
    assert scopes == {"s3": ["Environment", "Owner"], "ec2:instance": ["Environment", "Owner"]}


def test_load_scopes_invalid_json_falls_back(drift_reporter, monkeypatch):
    monkeypatch.setenv("DRIFT_TAG_SCOPES", "{broken")
    monkeypatch.setenv("REQUIRED_TAG_KEYS", "Owner")
    monkeypatch.setenv("RESOURCE_TYPE_FILTERS", "s3")
    assert drift_reporter._load_scopes() == {"s3": ["Owner"]}


def test_evaluate_type_classifies_resources(drift_reporter):
    pages = {
        "s3": [[
            {"arn": "arn:aws:s3:::compliant", "tags": {"Environment": "p", "Owner": "o", "DataClassification": "i"}},
            {"arn": "arn:aws:s3:::excluded", "tags": {"tagging:no-remediate": "y"}},
            {"arn": "arn:aws:s3:::drifted", "tags": {"Environment": "p"}},
        ]]
    }
    drift_reporter._CLIENTS["resourcegroupstaggingapi"] = FakeResourceGroupsTaggingAPI(pages)
    result = drift_reporter._evaluate_type("s3", _SCOPES["s3"], ["tagging:no-remediate"])
    assert result["scanned"] == 3
    assert result["compliant"] == 1
    assert result["excluded"] == 1
    assert result["drifted"] == 1
    missing = result["drifted_resources"][0]["missing_tag_keys"]
    assert set(missing) == {"Owner", "DataClassification"}


def test_iter_resources_follows_pagination(drift_reporter):
    pages = {
        "s3": [
            [{"arn": "arn:aws:s3:::a", "tags": {}}],
            [{"arn": "arn:aws:s3:::b", "tags": {}}],
        ]
    }
    drift_reporter._CLIENTS["resourcegroupstaggingapi"] = FakeResourceGroupsTaggingAPI(pages)
    arns = [r["arn"] for r in drift_reporter._iter_resources("s3")]
    assert arns == ["arn:aws:s3:::a", "arn:aws:s3:::b"]


# --------------------------------------------------------------------------- #
# Handler integration
# --------------------------------------------------------------------------- #

def _fixture_pages():
    return {
        "s3": [[
            {"arn": "arn:aws:s3:::ok", "tags": {"Environment": "p", "Owner": "o", "DataClassification": "i"}},
            {"arn": "arn:aws:s3:::skip", "tags": {"tagging:no-remediate": "y"}},
            {"arn": "arn:aws:s3:::bad1", "tags": {"Environment": "p"}},
        ]],
        "ec2:instance": [[
            {"arn": "arn:aws:ec2:us-east-1:123456789012:instance/i-bad", "tags": {}},
        ]],
    }


def test_handler_full_scan_writes_report_and_publishes(drift_reporter, monkeypatch):
    monkeypatch.setenv("DRIFT_TAG_SCOPES", json.dumps(_SCOPES))
    monkeypatch.setenv("REPORT_BUCKET", "drift-report-bucket")
    monkeypatch.setenv("REPORT_PREFIX", "tag-drift")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tag-drift")
    monkeypatch.setenv("ACCOUNT_ID", "123456789012")

    s3 = FakeS3()
    sns = RecordingSNS()
    drift_reporter._CLIENTS.update({
        "resourcegroupstaggingapi": FakeResourceGroupsTaggingAPI(_fixture_pages()),
        "s3": s3,
        "sns": sns,
    })

    result = drift_reporter.handler({})

    assert result["scanned"] == 4  # 3 s3 + 1 ec2
    assert result["compliant"] == 1
    assert result["excluded"] == 1
    assert result["drifted"] == 2
    assert result["report_location"].startswith("s3://drift-report-bucket/tag-drift/date=")

    # Report is KMS-encrypted and date-partitioned.
    assert len(s3.put_calls) == 1
    put = s3.put_calls[0]
    assert put["ServerSideEncryption"] == "aws:kms"
    body = json.loads(put["Body"].decode("utf-8"))
    assert body["summary"]["drifted"] == 2
    # Worst offender (most missing keys) sorts first.
    assert body["drifted_resources"][0]["arn"].endswith("instance/i-bad")

    assert len(sns.publish_calls) == 1
    assert "drifted" in sns.publish_calls[0]["Subject"]


def test_handler_without_bucket_or_topic_is_graceful(drift_reporter, monkeypatch):
    monkeypatch.setenv("DRIFT_TAG_SCOPES", json.dumps({"s3": ["Owner"]}))
    monkeypatch.delenv("REPORT_BUCKET", raising=False)
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)

    s3 = FakeS3()
    sns = RecordingSNS()
    drift_reporter._CLIENTS.update({
        "resourcegroupstaggingapi": FakeResourceGroupsTaggingAPI(
            {"s3": [[{"arn": "arn:aws:s3:::bad", "tags": {}}]]}
        ),
        "s3": s3,
        "sns": sns,
    })

    result = drift_reporter.handler({})

    assert result["drifted"] == 1
    assert result["report_location"] is None
    assert s3.put_calls == []      # no bucket -> no put
    assert sns.publish_calls == []  # no topic -> no publish


def test_handler_uses_fallback_scopes(drift_reporter, monkeypatch):
    monkeypatch.delenv("DRIFT_TAG_SCOPES", raising=False)
    monkeypatch.setenv("REQUIRED_TAG_KEYS", "Owner")
    monkeypatch.setenv("RESOURCE_TYPE_FILTERS", "s3")

    drift_reporter._CLIENTS.update({
        "resourcegroupstaggingapi": FakeResourceGroupsTaggingAPI(
            {"s3": [[
                {"arn": "arn:aws:s3:::has-owner", "tags": {"Owner": "o"}},
                {"arn": "arn:aws:s3:::no-owner", "tags": {"Environment": "p"}},
            ]]}
        ),
        "s3": FakeS3(),
        "sns": RecordingSNS(),
    })

    result = drift_reporter.handler({})
    assert result["scanned"] == 2
    assert result["compliant"] == 1
    assert result["drifted"] == 1
