"""Unit tests for the tag auto-remediation handler."""

from __future__ import annotations

import json

import pytest

from fakes import FakeRDS, FakeS3, RecordingSNS, RecordingTagging

pytestmark = pytest.mark.usefixtures("clear_tag_env", "reset_clients")

_DEFAULTS = {
    "Owner": "platform-team",
    "Team": "platform",
    "CostCenter": "0000",
    "DataClassification": "internal",
}
_REQUIRED = "Environment,Owner,Team,CostCenter,DataClassification"


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

def test_env_bool_truthy_and_falsey(remediator, monkeypatch):
    for truthy in ("1", "true", "YES", "On"):
        monkeypatch.setenv("DRY_RUN", truthy)
        assert remediator._env_bool("DRY_RUN", False) is True
    for falsey in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("DRY_RUN", falsey)
        assert remediator._env_bool("DRY_RUN", True) is False
    monkeypatch.delenv("DRY_RUN", raising=False)
    assert remediator._env_bool("DRY_RUN", True) is True


def test_load_default_tag_values(remediator, monkeypatch):
    monkeypatch.setenv("DEFAULT_TAG_VALUES", json.dumps(_DEFAULTS))
    assert remediator._load_default_tag_values() == _DEFAULTS


def test_load_default_tag_values_invalid_json_is_empty(remediator, monkeypatch):
    monkeypatch.setenv("DEFAULT_TAG_VALUES", "{not json")
    assert remediator._load_default_tag_values() == {}


def test_load_default_tag_values_non_object_is_empty(remediator, monkeypatch):
    monkeypatch.setenv("DEFAULT_TAG_VALUES", "[1, 2, 3]")
    assert remediator._load_default_tag_values() == {}


def test_parse_csv_env_trims_and_drops_blanks(remediator, monkeypatch):
    monkeypatch.setenv("REQUIRED_TAG_KEYS", " Environment , Owner ,, Team ")
    assert remediator._parse_csv_env("REQUIRED_TAG_KEYS") == ["Environment", "Owner", "Team"]


@pytest.mark.parametrize(
    "rtype,rid,expected",
    [
        ("AWS::S3::Bucket", "my-bucket", "arn:aws:s3:::my-bucket"),
        ("AWS::EC2::Instance", "i-1", "arn:aws:ec2:us-east-1:123456789012:instance/i-1"),
        ("AWS::EC2::Volume", "vol-1", "arn:aws:ec2:us-east-1:123456789012:volume/vol-1"),
        ("AWS::RDS::DBInstance", "mydb", "arn:aws:rds:us-east-1:123456789012:db:mydb"),
        ("AWS::DynamoDB::Table", "t", "arn:aws:dynamodb:us-east-1:123456789012:table/t"),
    ],
)
def test_build_arn_per_resource_type(remediator, rtype, rid, expected):
    assert remediator._build_arn(rtype, rid, "us-east-1", "123456789012", "aws") == expected


def test_build_arn_passthrough(remediator):
    arn = "arn:aws:s3:::already-an-arn"
    assert remediator._build_arn("AWS::S3::Bucket", arn, "us-east-1", "123456789012", "aws") == arn


def test_build_arn_unknown_type_is_none(remediator):
    assert remediator._build_arn("AWS::Unknown::Thing", "x", "us-east-1", "123456789012", "aws") is None


def test_is_excluded(remediator):
    assert remediator._is_excluded({"tagging:no-remediate": "y"}, ["tagging:no-remediate"]) is True
    assert remediator._is_excluded({"Owner": "x"}, ["tagging:no-remediate"]) is False


def test_tags_to_apply_only_missing_keys_with_defaults(remediator):
    current = {"Owner": "already-set"}
    required = ["Environment", "Owner", "Team", "CostCenter", "DataClassification"]
    to_apply = remediator._tags_to_apply(current, _DEFAULTS, required)
    # Owner present -> untouched; Environment has no default -> not invented.
    assert "Owner" not in to_apply
    assert "Environment" not in to_apply
    assert to_apply == {"Team": "platform", "CostCenter": "0000", "DataClassification": "internal"}


def test_normalize_targets_skips_compliant_config_event(remediator):
    event = {
        "detail": {
            "resourceId": "i-abc",
            "resourceType": "AWS::EC2::Instance",
            "newEvaluationResult": {"complianceType": "COMPLIANT"},
        }
    }
    assert remediator._normalize_targets(event, "us-east-1", "123456789012", "aws") == []


def test_normalize_targets_non_compliant_config_event(remediator):
    event = {
        "detail": {
            "resourceId": "i-abc",
            "resourceType": "AWS::EC2::Instance",
            "awsRegion": "us-east-1",
            "awsAccountId": "123456789012",
            "newEvaluationResult": {"complianceType": "NON_COMPLIANT"},
        }
    }
    targets = remediator._normalize_targets(event, "us-east-1", "123456789012", "aws")
    assert len(targets) == 1
    assert targets[0]["arn"] == "arn:aws:ec2:us-east-1:123456789012:instance/i-abc"


def test_normalize_targets_direct_resource_id_unknown_type_yields_nothing(remediator):
    event = {"resource_id": "x", "resource_type": "AWS::Unknown::Thing"}
    assert remediator._normalize_targets(event, "us-east-1", "123456789012", "aws") == []


# --------------------------------------------------------------------------- #
# Handler integration (fakes injected)
# --------------------------------------------------------------------------- #

def _configure(monkeypatch, dry_run=False):
    monkeypatch.setenv("DEFAULT_TAG_VALUES", json.dumps(_DEFAULTS))
    monkeypatch.setenv("REQUIRED_TAG_KEYS", _REQUIRED)
    monkeypatch.setenv("ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("PARTITION", "aws")
    monkeypatch.setenv("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:tag-remediation")
    if dry_run:
        monkeypatch.setenv("DRY_RUN", "true")


def test_handler_tags_untagged_bucket(remediator, monkeypatch):
    _configure(monkeypatch)
    s3 = FakeS3(bucket_tags={})  # no tag set -> untagged
    tagging = RecordingTagging()
    sns = RecordingSNS()
    remediator._CLIENTS.update({"s3": s3, "resourcegroupstaggingapi": tagging, "sns": sns})

    event = {"resource_arn": "arn:aws:s3:::my-bucket",
             "resource_type": "AWS::S3::Bucket", "resource_id": "my-bucket"}
    result = remediator.handler(event)

    assert result["evaluated"] == 1
    assert result["remediated"] == 1
    assert len(tagging.tag_calls) == 1
    applied = tagging.tag_calls[0]["tags"]
    # Environment has no default -> never invented.
    assert "Environment" not in applied
    assert applied == {"Owner": "platform-team", "Team": "platform",
                       "CostCenter": "0000", "DataClassification": "internal"}
    assert len(sns.publish_calls) == 1


def test_handler_never_overwrites_existing_tag(remediator, monkeypatch):
    _configure(monkeypatch)
    s3 = FakeS3(bucket_tags={"my-bucket": {"Owner": "real-owner"}})
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"s3": s3, "resourcegroupstaggingapi": tagging,
                                "sns": RecordingSNS()})

    event = {"resource_arn": "arn:aws:s3:::my-bucket",
             "resource_type": "AWS::S3::Bucket", "resource_id": "my-bucket"}
    remediator.handler(event)

    applied = tagging.tag_calls[0]["tags"]
    assert "Owner" not in applied  # existing Owner preserved
    assert set(applied) == {"Team", "CostCenter", "DataClassification"}


def test_handler_skips_excluded_resource(remediator, monkeypatch):
    _configure(monkeypatch)
    s3 = FakeS3(bucket_tags={"my-bucket": {"tagging:no-remediate": "yes"}})
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"s3": s3, "resourcegroupstaggingapi": tagging,
                                "sns": RecordingSNS()})

    event = {"resource_arn": "arn:aws:s3:::my-bucket",
             "resource_type": "AWS::S3::Bucket", "resource_id": "my-bucket"}
    result = remediator.handler(event)

    assert result["remediated"] == 0
    assert tagging.tag_calls == []
    assert result["results"][0]["status"] == "excluded"


def test_handler_compliant_config_event_writes_nothing(remediator, monkeypatch):
    _configure(monkeypatch)
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"resourcegroupstaggingapi": tagging, "sns": RecordingSNS()})

    event = {"detail": {"resourceId": "i-abc", "resourceType": "AWS::EC2::Instance",
                        "newEvaluationResult": {"complianceType": "COMPLIANT"}}}
    result = remediator.handler(event)

    assert result["evaluated"] == 0
    assert tagging.tag_calls == []


def test_handler_fully_tagged_is_compliant(remediator, monkeypatch):
    _configure(monkeypatch)
    all_tags = {"Environment": "prod", "Owner": "o", "Team": "t",
                "CostCenter": "1", "DataClassification": "internal"}
    s3 = FakeS3(bucket_tags={"my-bucket": all_tags})
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"s3": s3, "resourcegroupstaggingapi": tagging,
                                "sns": RecordingSNS()})

    event = {"resource_arn": "arn:aws:s3:::my-bucket",
             "resource_type": "AWS::S3::Bucket", "resource_id": "my-bucket"}
    result = remediator.handler(event)

    assert result["remediated"] == 0
    assert result["results"][0]["status"] == "compliant"
    assert tagging.tag_calls == []


def test_handler_dry_run_reports_without_writing(remediator, monkeypatch):
    _configure(monkeypatch, dry_run=True)
    s3 = FakeS3(bucket_tags={})
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"s3": s3, "resourcegroupstaggingapi": tagging,
                                "sns": RecordingSNS()})

    event = {"resource_arn": "arn:aws:s3:::my-bucket",
             "resource_type": "AWS::S3::Bucket", "resource_id": "my-bucket"}
    result = remediator.handler(event)

    assert result["dry_run"] is True
    assert tagging.tag_calls == []  # nothing written in dry-run
    entry = result["results"][0]
    assert entry["status"] == "dry-run"
    assert entry["applied_tags"]  # the would-be changes are reported


def test_handler_builds_arn_for_rds_resource_id(remediator, monkeypatch):
    _configure(monkeypatch)
    expected_arn = "arn:aws:rds:us-east-1:123456789012:db:mydb"
    rds = FakeRDS(tags_by_arn={expected_arn: {}})
    tagging = RecordingTagging()
    remediator._CLIENTS.update({"rds": rds, "resourcegroupstaggingapi": tagging,
                                "sns": RecordingSNS()})

    event = {"resource_id": "mydb", "resource_type": "AWS::RDS::DBInstance"}
    remediator.handler(event)

    assert tagging.tag_calls[0]["arns"] == [expected_arn]
