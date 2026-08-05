# Reporting layer: a periodic, read-only inventory of tag drift. The preventive
# tag policy and the detective Config rules each answer a narrow question; this
# layer produces the single, human-readable "what is currently untagged?" report
# that owners actually act on.
#
# A scheduled function scans resources through the Resource Groups Tagging API,
# compares each against the required-key set for its type, writes a
# date-partitioned JSON report to an encrypted S3 bucket, and publishes a
# summary to a dedicated SNS topic. It writes nothing back to any scanned
# resource — remediation is a separate, opt-in concern.
#
# The layer is self-contained (its own key, topic, and bucket) so it can be
# enabled independently of the remediation layer.

locals {
  drift_count                 = var.enable_drift_reporting ? 1 : 0
  drift_reporter_function_name = "${var.name_prefix}-tag-drift-reporter"

  # Deterministic, account-scoped report bucket name unless the caller supplies
  # one. Bucket names are globally unique, so the account id keeps it collision
  # free across accounts running this configuration.
  drift_report_bucket_name = coalesce(
    var.drift_report_bucket_name,
    "${var.name_prefix}-drift-reports-${data.aws_caller_identity.current.account_id}"
  )
}

# ---------------------------------------------------------------------------
# Encryption key for the report bucket, log group, and notification topic
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "drift_kms" {
  count = local.drift_count

  statement {
    sid     = "EnableRootAccountAdmin"
    effect  = "Allow"
    actions = ["kms:*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }

    resources = ["*"]
  }

  statement {
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }

    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]

    resources = ["*"]

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.drift_reporter_function_name}*"]
    }
  }

  statement {
    sid    = "AllowSNSService"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }

    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "drift" {
  count                   = local.drift_count
  description             = "Encrypts the tag drift report bucket, log group, and notification topic."
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.drift_kms[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-drift-reporting" })
}

resource "aws_kms_alias" "drift" {
  count         = local.drift_count
  name          = "alias/${var.name_prefix}-drift-reporting"
  target_key_id = aws_kms_key.drift[0].key_id
}

# ---------------------------------------------------------------------------
# Report storage
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "drift_reports" {
  count  = local.drift_count
  bucket = local.drift_report_bucket_name

  tags = merge(var.default_tags, { Name = local.drift_report_bucket_name })
}

resource "aws_s3_bucket_ownership_controls" "drift_reports" {
  count  = local.drift_count
  bucket = aws_s3_bucket.drift_reports[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "drift_reports" {
  count                   = local.drift_count
  bucket                  = aws_s3_bucket.drift_reports[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "drift_reports" {
  count  = local.drift_count
  bucket = aws_s3_bucket.drift_reports[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "drift_reports" {
  count  = local.drift_count
  bucket = aws_s3_bucket.drift_reports[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.drift[0].arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "drift_reports" {
  count  = local.drift_count
  bucket = aws_s3_bucket.drift_reports[0].id

  rule {
    id     = "expire-drift-reports"
    status = "Enabled"

    filter {}

    expiration {
      days = var.drift_report_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

data "aws_iam_policy_document" "drift_bucket" {
  count = local.drift_count

  statement {
    sid    = "DenyInsecureTransport"
    effect = "Deny"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    actions   = ["s3:*"]
    resources = [aws_s3_bucket.drift_reports[0].arn, "${aws_s3_bucket.drift_reports[0].arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "drift_reports" {
  count  = local.drift_count
  bucket = aws_s3_bucket.drift_reports[0].id
  policy = data.aws_iam_policy_document.drift_bucket[0].json
}

# ---------------------------------------------------------------------------
# Notification topic
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "drift" {
  count             = local.drift_count
  name              = "${var.name_prefix}-tag-drift"
  kms_master_key_id = aws_kms_key.drift[0].key_id

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-drift" })
}

resource "aws_sns_topic_subscription" "drift_email" {
  for_each = var.enable_drift_reporting ? toset(var.drift_report_email_addresses) : toset([])

  topic_arn = aws_sns_topic.drift[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# ---------------------------------------------------------------------------
# Drift reporter function
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "tag_drift_reporter" {
  count             = local.drift_count
  name              = "/aws/lambda/${local.drift_reporter_function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.drift[0].arn

  tags = merge(var.default_tags, { Name = local.drift_reporter_function_name })
}

data "archive_file" "tag_drift_reporter" {
  count       = local.drift_count
  type        = "zip"
  source_dir  = "${path.module}/lambda/tag-drift-reporter"
  output_path = "${path.module}/.build/tag-drift-reporter.zip"
  excludes    = ["README.md", "requirements.txt", "__pycache__"]
}

data "aws_iam_policy_document" "drift_reporter_assume" {
  count = local.drift_count

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "tag_drift_reporter" {
  count              = local.drift_count
  name               = "${var.name_prefix}-tag-drift-reporter"
  assume_role_policy = data.aws_iam_policy_document.drift_reporter_assume[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-drift-reporter" })
}

data "aws_iam_policy_document" "drift_reporter" {
  count = local.drift_count

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.tag_drift_reporter[0].arn}:*"]
  }

  # Read-only tag discovery across services. The target set is the whole
  # account, so the read actions are scoped by action rather than by ARN.
  statement {
    sid    = "ReadResourceTags"
    effect = "Allow"

    actions = [
      "tag:GetResources",
      "tag:GetTagKeys",
      "tag:GetTagValues",
    ]

    resources = ["*"]
  }

  statement {
    sid       = "WriteReport"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.drift_reports[0].arn}/*"]
  }

  statement {
    sid       = "PublishSummary"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.drift[0].arn]
  }

  statement {
    sid       = "UseReportingKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = [aws_kms_key.drift[0].arn]
  }

  statement {
    sid       = "Tracing"
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "tag_drift_reporter" {
  count  = local.drift_count
  name   = "tag-drift-reporter"
  role   = aws_iam_role.tag_drift_reporter[0].id
  policy = data.aws_iam_policy_document.drift_reporter[0].json
}

resource "aws_lambda_function" "tag_drift_reporter" {
  count            = local.drift_count
  function_name    = local.drift_reporter_function_name
  role             = aws_iam_role.tag_drift_reporter[0].arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.tag_drift_reporter[0].output_path
  source_code_hash = data.archive_file.tag_drift_reporter[0].output_base64sha256
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_mb

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      DRIFT_TAG_SCOPES       = jsonencode(var.drift_resource_type_scopes)
      REQUIRED_TAG_KEYS      = join(",", keys(var.required_tags))
      EXCLUSION_TAG_KEYS     = join(",", var.remediation_exclusion_tag_keys)
      REPORT_BUCKET          = aws_s3_bucket.drift_reports[0].id
      REPORT_PREFIX          = "tag-drift"
      SNS_TOPIC_ARN          = aws_sns_topic.drift[0].arn
      MAX_DRIFTED_IN_SUMMARY = tostring(var.drift_summary_limit)
      ACCOUNT_ID             = data.aws_caller_identity.current.account_id
      LOG_LEVEL              = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.tag_drift_reporter,
    aws_iam_role_policy.tag_drift_reporter,
  ]

  tags = merge(var.default_tags, { Name = local.drift_reporter_function_name })
}

# ---------------------------------------------------------------------------
# Schedule — periodic drift scan
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "drift_schedule" {
  count               = local.drift_count
  name                = "${var.name_prefix}-tag-drift-schedule"
  description         = "Triggers the tag drift report on a fixed schedule."
  schedule_expression = var.drift_report_schedule_expression

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-drift-schedule" })
}

resource "aws_cloudwatch_event_target" "drift_schedule" {
  count = local.drift_count
  rule  = aws_cloudwatch_event_rule.drift_schedule[0].name
  arn   = aws_lambda_function.tag_drift_reporter[0].arn
}

resource "aws_lambda_permission" "drift_schedule" {
  count         = local.drift_count
  statement_id  = "AllowScheduledInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tag_drift_reporter[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.drift_schedule[0].arn
}
