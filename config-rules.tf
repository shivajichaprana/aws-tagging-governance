# Detective tag-governance controls: AWS Config REQUIRED_TAGS rules that flag
# resources missing the tag keys the organization standardizes on. Each rule is
# scoped to a single resource type so different resource types can carry a
# different required-key set — a database may require CostCenter while a bucket
# requires DataClassification.
#
# These rules complement the preventive Organizations tag policy defined
# alongside them: the tag policy constrains allowed values at tag-modification
# time, while these Config rules continuously evaluate already-provisioned
# resources and mark the non-compliant ones for reporting and remediation.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  # DNS-safe suffix for each rule name derived from the Config resource type:
  # "AWS::EC2::Instance" -> "ec2-instance".
  config_rule_suffix = {
    for rtype in keys(var.config_rule_resource_scopes) :
    rtype => lower(replace(replace(rtype, "AWS::", ""), "::", "-"))
  }

  # Pack each resource type's required keys into the REQUIRED_TAGS managed-rule
  # input schema (tag1Key..tag6Key plus optional comma-joined tag{N}Value lists
  # sourced from the shared required_tags definition). A key with no configured
  # allowed values contributes only its tag{N}Key, leaving the value
  # unrestricted. The contains() guard keeps rendering safe for a key that is
  # not declared in required_tags; the rule precondition below turns that into a
  # clear plan-time failure.
  config_rule_parameters = {
    for rtype, keys in var.config_rule_resource_scopes : rtype => jsonencode(
      merge([
        for idx, key in keys : merge(
          { "tag${idx + 1}Key" = key },
          (contains(keys(var.required_tags), key) && length(var.required_tags[key].allowed_values) > 0) ?
          { "tag${idx + 1}Value" = join(",", var.required_tags[key].allowed_values) } : {}
        )
      ]...)
    )
  }

  create_recorder = var.create_config_recorder ? 1 : 0

  # Deterministic, account-scoped bucket name unless the caller supplies one.
  config_bucket_name = coalesce(
    var.config_s3_bucket_name,
    "${var.name_prefix}-config-${data.aws_caller_identity.current.account_id}"
  )
}

# ---------------------------------------------------------------------------
# REQUIRED_TAGS rules — one per in-scope resource type (per-resource scoping)
# ---------------------------------------------------------------------------
resource "aws_config_config_rule" "required_tags" {
  for_each = var.enable_config_rules ? var.config_rule_resource_scopes : {}

  name        = "${var.name_prefix}-required-tags-${local.config_rule_suffix[each.key]}"
  description = "Flags ${each.key} resources missing one or more required tag keys."

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }

  # Scope the evaluation to a single resource type so the required-key set is
  # tailored to it rather than applied uniformly across the account.
  scope {
    compliance_resource_types = [each.key]
  }

  input_parameters = local.config_rule_parameters[each.key]

  tags = merge(var.default_tags, {
    Name = "${var.name_prefix}-required-tags-${local.config_rule_suffix[each.key]}"
  })

  lifecycle {
    precondition {
      condition     = length(each.value) >= 1 && length(each.value) <= 6
      error_message = "Each resource scope in config_rule_resource_scopes must list between 1 and 6 tag keys (the REQUIRED_TAGS managed rule supports at most six)."
    }
    precondition {
      condition     = alltrue([for k in each.value : contains(keys(var.required_tags), k)])
      error_message = "Every tag key referenced in config_rule_resource_scopes must also be declared in required_tags."
    }
  }

  # A rule can only evaluate resources once a configuration recorder is active.
  # When this configuration does not manage the recorder, the reference resolves
  # to an empty set and the dependency is a no-op.
  depends_on = [aws_config_configuration_recorder.this]
}

# ---------------------------------------------------------------------------
# Optional configuration recorder
#
# In most organizations AWS Config is enabled centrally (via a landing zone or
# a security-compliance baseline), so recorder creation is off by default and
# the rules above attach to whichever recorder already exists in the account.
# Enable it for standalone accounts that do not yet record configuration items.
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "config" {
  count  = local.create_recorder
  bucket = local.config_bucket_name

  tags = merge(var.default_tags, { Name = local.config_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "config" {
  count  = local.create_recorder
  bucket = aws_s3_bucket.config[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count                   = local.create_recorder
  bucket                  = aws_s3_bucket.config[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "config" {
  count  = local.create_recorder
  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = local.create_recorder
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "config" {
  count  = local.create_recorder
  bucket = aws_s3_bucket.config[0].id

  rule {
    id     = "expire-config-history"
    status = "Enabled"

    filter {}

    expiration {
      days = var.config_log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "config_bucket" {
  count = local.create_recorder

  statement {
    sid    = "AWSConfigBucketPermissionsCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config[0].arn]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AWSConfigBucketDelivery"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.config[0].arn, "${aws_s3_bucket.config[0].arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count  = local.create_recorder
  bucket = aws_s3_bucket.config[0].id
  policy = data.aws_iam_policy_document.config_bucket[0].json
}

data "aws_iam_policy_document" "config_assume" {
  count = local.create_recorder

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = local.create_recorder
  name               = "${var.name_prefix}-config-recorder"
  assume_role_policy = data.aws_iam_policy_document.config_assume[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-config-recorder" })
}

# AWS-managed policy granting the Config service the read/describe access it
# needs to record configuration items.
resource "aws_iam_role_policy_attachment" "config_managed" {
  count      = local.create_recorder
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# Least-privilege delivery permissions scoped to the Config bucket path.
data "aws_iam_policy_document" "config_delivery" {
  count = local.create_recorder

  statement {
    sid       = "ConfigBucketAcl"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config[0].arn]
  }

  statement {
    sid       = "ConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  count  = local.create_recorder
  name   = "config-s3-delivery"
  role   = aws_iam_role.config[0].id
  policy = data.aws_iam_policy_document.config_delivery[0].json
}

resource "aws_config_configuration_recorder" "this" {
  count    = local.create_recorder
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  count          = local.create_recorder
  name           = "${var.name_prefix}-delivery"
  s3_bucket_name = aws_s3_bucket.config[0].id

  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config,
  ]
}

resource "aws_config_configuration_recorder_status" "this" {
  count      = local.create_recorder
  name       = aws_config_configuration_recorder.this[0].name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.this]
}
