# Remediation layer: closes the tag-governance loop by filling in the
# organization's default tag values on resources that the detective AWS Config
# rules flag as non-compliant, and notifying on the actions taken.
#
# The workflow has three entry points that share one function:
#   * event-driven — an EventBridge rule invokes the function on Config
#     compliance-change events (opt-in);
#   * AWS Config remediation — each required-tags rule can call the SSM
#     Automation document, which invokes the function (opt-in);
#   * manual — the SSM Automation document can be run on demand.
#
# Actuation is conservative by construction: the function only fills in missing
# required keys that have a safe default, never overwrites an existing value,
# and honours a per-resource exclusion tag.

data "aws_region" "current" {}

locals {
  remediation_count        = var.enable_remediation ? 1 : 0
  remediator_function_name = "${var.name_prefix}-tag-remediator"
  event_remediation_count  = var.enable_remediation && var.enable_event_driven_remediation ? 1 : 0

  config_remediation_scopes = (
    var.enable_remediation && var.enable_config_remediation && var.enable_config_rules
  ) ? var.config_rule_resource_scopes : {}
}

# ---------------------------------------------------------------------------
# Encryption key for the log group and notification topic
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "remediation_kms" {
  count = local.remediation_count

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
      values   = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/lambda/${local.remediator_function_name}*"]
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

resource "aws_kms_key" "remediation" {
  count                   = local.remediation_count
  description             = "Encrypts the tag remediation log group and notification topic."
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.remediation_kms[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-remediation" })
}

resource "aws_kms_alias" "remediation" {
  count         = local.remediation_count
  name          = "alias/${var.name_prefix}-remediation"
  target_key_id = aws_kms_key.remediation[0].key_id
}

# ---------------------------------------------------------------------------
# Notification topic
# ---------------------------------------------------------------------------
resource "aws_sns_topic" "remediation" {
  count             = local.remediation_count
  name              = "${var.name_prefix}-tag-remediation"
  kms_master_key_id = aws_kms_key.remediation[0].key_id

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-remediation" })
}

resource "aws_sns_topic_subscription" "remediation_email" {
  for_each = var.enable_remediation ? toset(var.notification_email_addresses) : toset([])

  topic_arn = aws_sns_topic.remediation[0].arn
  protocol  = "email"
  endpoint  = each.value
}

# ---------------------------------------------------------------------------
# Remediation function
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "tag_remediator" {
  count             = local.remediation_count
  name              = "/aws/lambda/${local.remediator_function_name}"
  retention_in_days = var.lambda_log_retention_days
  kms_key_id        = aws_kms_key.remediation[0].arn

  tags = merge(var.default_tags, { Name = local.remediator_function_name })
}

data "archive_file" "tag_remediator" {
  count       = local.remediation_count
  type        = "zip"
  source_dir  = "${path.module}/lambda/tag-remediator"
  output_path = "${path.module}/.build/tag-remediator.zip"
  excludes    = ["README.md", "requirements.txt", "__pycache__"]
}

data "aws_iam_policy_document" "remediator_assume" {
  count = local.remediation_count

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "tag_remediator" {
  count              = local.remediation_count
  name               = "${var.name_prefix}-tag-remediator"
  assume_role_policy = data.aws_iam_policy_document.remediator_assume[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-remediator" })
}

data "aws_iam_policy_document" "remediator" {
  count = local.remediation_count

  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.tag_remediator[0].arn}:*"]
  }

  # Read a resource's current tags and apply the missing default tags. The
  # target set is dynamic (any non-compliant resource), so the tag actions are
  # scoped by action rather than by resource ARN.
  statement {
    sid    = "ReadAndApplyTags"
    effect = "Allow"

    actions = [
      "tag:GetResources",
      "tag:TagResources",
      "ec2:DescribeTags",
      "ec2:CreateTags",
      "s3:GetBucketTagging",
      "s3:PutBucketTagging",
      "rds:ListTagsForResource",
      "rds:AddTagsToResource",
      "dynamodb:ListTagsOfResource",
      "dynamodb:TagResource",
    ]

    resources = ["*"]
  }

  statement {
    sid       = "PublishSummary"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.remediation[0].arn]
  }

  statement {
    sid       = "UseNotificationKey"
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:GenerateDataKey*"]
    resources = [aws_kms_key.remediation[0].arn]
  }

  statement {
    sid       = "Tracing"
    effect    = "Allow"
    actions   = ["xray:PutTraceSegments", "xray:PutTelemetryRecords"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "tag_remediator" {
  count  = local.remediation_count
  name   = "tag-remediator"
  role   = aws_iam_role.tag_remediator[0].id
  policy = data.aws_iam_policy_document.remediator[0].json
}

resource "aws_lambda_function" "tag_remediator" {
  count            = local.remediation_count
  function_name    = local.remediator_function_name
  role             = aws_iam_role.tag_remediator[0].arn
  runtime          = "python3.12"
  handler          = "handler.handler"
  filename         = data.archive_file.tag_remediator[0].output_path
  source_code_hash = data.archive_file.tag_remediator[0].output_base64sha256
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_mb

  tracing_config {
    mode = "Active"
  }

  environment {
    variables = {
      SNS_TOPIC_ARN      = aws_sns_topic.remediation[0].arn
      DEFAULT_TAG_VALUES = jsonencode(var.default_tag_values)
      REQUIRED_TAG_KEYS  = join(",", keys(var.required_tags))
      EXCLUSION_TAG_KEYS = join(",", var.remediation_exclusion_tag_keys)
      DRY_RUN            = tostring(var.remediation_dry_run)
      PARTITION          = data.aws_partition.current.partition
      ACCOUNT_ID         = data.aws_caller_identity.current.account_id
      LOG_LEVEL          = "INFO"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.tag_remediator,
    aws_iam_role_policy.tag_remediator,
  ]

  tags = merge(var.default_tags, { Name = local.remediator_function_name })
}

# ---------------------------------------------------------------------------
# Event-driven trigger (opt-in)
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_event_rule" "compliance_change" {
  count       = local.event_remediation_count
  name        = "${var.name_prefix}-tag-compliance-change"
  description = "Routes AWS Config non-compliant tag findings to the remediation function."

  event_pattern = jsonencode({
    source        = ["aws.config"]
    "detail-type" = ["Config Rules Compliance Change"]
    detail = {
      messageType = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-compliance-change" })
}

resource "aws_cloudwatch_event_target" "compliance_change" {
  count = local.event_remediation_count
  rule  = aws_cloudwatch_event_rule.compliance_change[0].name
  arn   = aws_lambda_function.tag_remediator[0].arn
}

resource "aws_lambda_permission" "events" {
  count         = local.event_remediation_count
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.tag_remediator[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_change[0].arn
}

# ---------------------------------------------------------------------------
# SSM Automation document + assume role
# ---------------------------------------------------------------------------
resource "aws_ssm_document" "tag_remediation" {
  count           = local.remediation_count
  name            = "${var.name_prefix}-tag-remediation"
  document_type   = "Automation"
  document_format = "YAML"
  content         = file("${path.module}/ssm/tag-remediation.yaml")

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-remediation" })
}

data "aws_iam_policy_document" "ssm_automation_assume" {
  count = local.remediation_count

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ssm.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "ssm_automation" {
  count              = local.remediation_count
  name               = "${var.name_prefix}-tag-remediation-automation"
  assume_role_policy = data.aws_iam_policy_document.ssm_automation_assume[0].json

  tags = merge(var.default_tags, { Name = "${var.name_prefix}-tag-remediation-automation" })
}

data "aws_iam_policy_document" "ssm_automation" {
  count = local.remediation_count

  statement {
    sid       = "InvokeRemediation"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [aws_lambda_function.tag_remediator[0].arn]
  }
}

resource "aws_iam_role_policy" "ssm_automation" {
  count  = local.remediation_count
  name   = "invoke-tag-remediator"
  role   = aws_iam_role.ssm_automation[0].id
  policy = data.aws_iam_policy_document.ssm_automation[0].json
}

# ---------------------------------------------------------------------------
# AWS Config remediation configuration (opt-in) — one per required-tags rule
# ---------------------------------------------------------------------------
resource "aws_config_remediation_configuration" "tag_remediation" {
  for_each = local.config_remediation_scopes

  config_rule_name = aws_config_config_rule.required_tags[each.key].name
  resource_type    = each.key
  target_type      = "SSM_DOCUMENT"
  target_id        = aws_ssm_document.tag_remediation[0].name

  automatic                  = var.config_remediation_automatic
  maximum_automatic_attempts = var.config_remediation_automatic ? var.config_remediation_maximum_attempts : null
  retry_attempt_seconds      = var.config_remediation_automatic ? var.config_remediation_retry_seconds : null

  parameter {
    name         = "AutomationAssumeRole"
    static_value = aws_iam_role.ssm_automation[0].arn
  }

  parameter {
    name           = "ResourceId"
    resource_value = "RESOURCE_ID"
  }

  parameter {
    name         = "ResourceType"
    static_value = each.key
  }

  parameter {
    name         = "RemediationFunctionName"
    static_value = aws_lambda_function.tag_remediator[0].function_name
  }
}
