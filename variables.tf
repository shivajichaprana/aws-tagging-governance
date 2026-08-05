variable "aws_region" {
  description = "AWS region for the provider. Organizations is a global service, but the provider still requires a region."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]$", var.aws_region))
    error_message = "aws_region must be a valid AWS region identifier, for example us-east-1."
  }
}

variable "name_prefix" {
  description = "Prefix applied to the names of governance resources so they are easy to identify across the organization."
  type        = string
  default     = "tag-governance"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 3-32 lowercase alphanumeric or hyphen characters and start with a letter."
  }
}

variable "default_tags" {
  description = "Tags applied to every resource this configuration manages."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
    Component = "tag-governance"
  }
}

# Declarative definition of the organization's required tags. Each entry maps a
# tag key to its allowed values and the resource types the value is enforced on.
# An empty allowed_values list means the key is required but the value is free
# form; an empty enforced_for list means non-compliant values are reported but
# not blocked at tag-modification time.
variable "required_tags" {
  description = "Map of required tag key to allowed values and the resource types the value is enforced for."
  type = map(object({
    allowed_values = optional(list(string), [])
    enforced_for   = optional(list(string), [])
  }))

  default = {
    Environment = {
      allowed_values = ["production", "staging", "development", "sandbox"]
      enforced_for   = ["ec2:instance", "ec2:volume", "s3:bucket", "rds:db"]
    }
    Owner = {
      allowed_values = []
      enforced_for   = []
    }
    CostCenter = {
      allowed_values = []
      enforced_for   = ["ec2:instance", "rds:db"]
    }
    Project = {
      allowed_values = []
      enforced_for   = []
    }
    DataClassification = {
      allowed_values = ["public", "internal", "confidential", "restricted"]
      enforced_for   = ["s3:bucket", "dynamodb:table"]
    }
  }

  validation {
    condition     = length(var.required_tags) > 0
    error_message = "required_tags must declare at least one tag key."
  }

  validation {
    condition = alltrue([
      for k in keys(var.required_tags) : can(regex("^[A-Za-z0-9 _.:/=+@-]{1,128}$", k))
    ])
    error_message = "Each tag key must be 1-128 characters using the AWS-permitted tag key character set."
  }
}

# Organization roots, organizational units, or account IDs the tag policy is
# attached to. Leave empty to create the policy without attaching it (useful
# for a review-first rollout). Use placeholder values such as "r-abcd" or
# "ou-abcd-11111111" until the real targets are known.
variable "policy_target_ids" {
  description = "Organization root, OU, or account IDs to attach the tag policy to."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for t in var.policy_target_ids : can(regex("^(r-[0-9a-z]{4,32}|ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}|[0-9]{12})$", t))
    ])
    error_message = "Each target must be an organization root (r-*), OU (ou-*), or 12-digit account ID."
  }
}

# Toggle for the detective AWS Config REQUIRED_TAGS rules. Leave enabled to
# create one rule per in-scope resource type; disable to manage only the
# preventive Organizations tag policy.
variable "enable_config_rules" {
  description = "Whether to create the AWS Config required-tags rules."
  type        = bool
  default     = true
}

# Per-resource scoping for the REQUIRED_TAGS rules: maps each AWS Config
# resource type to the tag keys required on it. Keys must be declared in
# required_tags (their allowed values are sourced from there). The REQUIRED_TAGS
# managed rule supports at most six keys per resource type.
variable "config_rule_resource_scopes" {
  description = "Map of AWS Config resource type to the required tag keys enforced on it (1-6 keys, each declared in required_tags)."
  type        = map(list(string))

  default = {
    "AWS::EC2::Instance"   = ["Environment", "Owner", "CostCenter"]
    "AWS::EC2::Volume"     = ["Environment", "Owner"]
    "AWS::S3::Bucket"      = ["Environment", "Owner", "DataClassification"]
    "AWS::RDS::DBInstance" = ["Environment", "Owner", "CostCenter"]
    "AWS::DynamoDB::Table" = ["Environment", "Owner", "DataClassification"]
  }

  validation {
    condition = alltrue([
      for rtype in keys(var.config_rule_resource_scopes) : can(regex("^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$", rtype))
    ])
    error_message = "Each key must be an AWS Config resource type such as AWS::EC2::Instance."
  }

  validation {
    condition = alltrue([
      for keys in values(var.config_rule_resource_scopes) : length(keys) >= 1 && length(keys) <= 6
    ])
    error_message = "Each resource type must list between 1 and 6 required tag keys (REQUIRED_TAGS supports at most six)."
  }
}

# Optional: create an AWS Config configuration recorder in this account. Off by
# default because Config is usually enabled centrally; enable for standalone
# accounts that do not yet record configuration items.
variable "create_config_recorder" {
  description = "Whether to provision an AWS Config recorder, delivery channel, and delivery bucket in this account."
  type        = bool
  default     = false
}

# Optional explicit name for the Config delivery bucket. Defaults to a
# deterministic, account-scoped name when null.
variable "config_s3_bucket_name" {
  description = "Name of the S3 bucket for Config delivery. Null derives a deterministic account-scoped name."
  type        = string
  default     = null

  validation {
    condition     = var.config_s3_bucket_name == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", coalesce(var.config_s3_bucket_name, "placeholder-bucket")))
    error_message = "config_s3_bucket_name must be a valid S3 bucket name or null."
  }
}

# Retention for delivered Config snapshots/history in the delivery bucket.
variable "config_log_retention_days" {
  description = "Days to retain Config delivery objects before expiration."
  type        = number
  default     = 365

  validation {
    condition     = var.config_log_retention_days >= 1 && var.config_log_retention_days <= 3650
    error_message = "config_log_retention_days must be between 1 and 3650."
  }
}

# ---------------------------------------------------------------------------
# Remediation layer
# ---------------------------------------------------------------------------

# Master toggle for the automated remediation workflow (function, notification
# topic, and SSM Automation document). Enabled by default so the capability is
# provisioned; actuation is opt-in via the trigger toggles below.
variable "enable_remediation" {
  description = "Whether to create the tag remediation function, topic, and SSM Automation document."
  type        = bool
  default     = true
}

# Default tag values applied to a non-compliant resource for any required key
# that is missing. Only keys listed here are auto-remediated: a key whose value
# cannot be safely guessed (such as Environment) is intentionally omitted so the
# workflow never writes a value that would itself be non-compliant. Existing tag
# values are never overwritten.
variable "default_tag_values" {
  description = "Map of required tag key to the default value applied when the key is missing from a resource."
  type        = map(string)

  default = {
    Owner              = "unassigned"
    CostCenter         = "unallocated"
    Project            = "untracked"
    DataClassification = "internal"
  }

  validation {
    condition = alltrue([
      for k in keys(var.default_tag_values) : can(regex("^[A-Za-z0-9 _.:/=+@-]{1,128}$", k))
    ])
    error_message = "Each default tag key must use the AWS-permitted tag key character set."
  }
}

# Resources carrying any of these tag keys are skipped by the remediation
# workflow, giving owners a documented opt-out.
variable "remediation_exclusion_tag_keys" {
  description = "Tag keys that exclude a resource from automated remediation."
  type        = list(string)
  default     = ["tagging:no-remediate"]

  validation {
    condition     = length(var.remediation_exclusion_tag_keys) > 0
    error_message = "Provide at least one exclusion tag key."
  }
}

# When true the function evaluates and reports the changes it would make without
# writing any tag. Leave false for the function to apply default tags.
variable "remediation_dry_run" {
  description = "Run the remediation function in report-only mode without writing tags."
  type        = bool
  default     = false
}

# Trigger the remediation function automatically when AWS Config reports a
# resource as non-compliant. Off by default for a review-first rollout; the
# function can be invoked manually or via the SSM document until enabled.
variable "enable_event_driven_remediation" {
  description = "Whether to invoke the remediation function on AWS Config compliance-change events."
  type        = bool
  default     = false
}

# Wire each AWS Config required-tags rule to the SSM Automation document as a
# remediation configuration. Off by default; enable to close the detect-to-fix
# loop through AWS Config's native remediation.
variable "enable_config_remediation" {
  description = "Whether to attach an AWS Config remediation configuration to each required-tags rule."
  type        = bool
  default     = false
}

# When enable_config_remediation is on, whether AWS Config applies the
# remediation automatically or requires a manual trigger per finding.
variable "config_remediation_automatic" {
  description = "Whether AWS Config remediation runs automatically rather than on manual trigger."
  type        = bool
  default     = false
}

variable "config_remediation_maximum_attempts" {
  description = "Maximum automatic remediation attempts within the retry window."
  type        = number
  default     = 5

  validation {
    condition     = var.config_remediation_maximum_attempts >= 1 && var.config_remediation_maximum_attempts <= 25
    error_message = "config_remediation_maximum_attempts must be between 1 and 25."
  }
}

variable "config_remediation_retry_seconds" {
  description = "Retry window in seconds for automatic AWS Config remediation attempts."
  type        = number
  default     = 300

  validation {
    condition     = var.config_remediation_retry_seconds >= 60 && var.config_remediation_retry_seconds <= 2678000
    error_message = "config_remediation_retry_seconds must be between 60 and 2678000."
  }
}

# Optional email addresses subscribed to the remediation notification topic.
variable "notification_email_addresses" {
  description = "Email addresses subscribed to the remediation notification topic."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for e in var.notification_email_addresses : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))
    ])
    error_message = "Each entry must be a valid email address."
  }
}

variable "lambda_timeout_seconds" {
  description = "Timeout for the remediation function."
  type        = number
  default     = 120

  validation {
    condition     = var.lambda_timeout_seconds >= 3 && var.lambda_timeout_seconds <= 900
    error_message = "lambda_timeout_seconds must be between 3 and 900."
  }
}

variable "lambda_memory_mb" {
  description = "Memory size for the remediation function."
  type        = number
  default     = 256

  validation {
    condition     = var.lambda_memory_mb >= 128 && var.lambda_memory_mb <= 10240
    error_message = "lambda_memory_mb must be between 128 and 10240."
  }
}

variable "lambda_log_retention_days" {
  description = "Retention for the remediation function's CloudWatch log group."
  type        = number
  default     = 90

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.lambda_log_retention_days)
    error_message = "lambda_log_retention_days must be a value CloudWatch Logs accepts."
  }
}

# ---------------------------------------------------------------------------
# Reporting layer
# ---------------------------------------------------------------------------

# Master toggle for the periodic tag-drift reporting workflow (scan function,
# report bucket, notification topic, and schedule). Enabled by default so the
# capability is provisioned; it is self-contained and can be toggled
# independently of the remediation layer.
variable "enable_drift_reporting" {
  description = "Whether to create the tag drift reporter, its report bucket, topic, and schedule."
  type        = bool
  default     = true
}

# Per-resource-type scoping for the drift scan: maps a Resource Groups Tagging
# API resource-type filter (for example "ec2:instance", "s3", or "rds:db") to
# the tag keys required on that type. Different types can require different
# keys, mirroring the detective Config rules.
variable "drift_resource_type_scopes" {
  description = "Map of Resource Groups Tagging API resource-type filter to the required tag keys reported as drift when missing."
  type        = map(list(string))

  default = {
    "ec2:instance"   = ["Environment", "Owner", "CostCenter"]
    "ec2:volume"     = ["Environment", "Owner"]
    "s3:bucket"      = ["Environment", "Owner", "DataClassification"]
    "rds:db"         = ["Environment", "Owner", "CostCenter"]
    "dynamodb:table" = ["Environment", "Owner", "DataClassification"]
  }

  validation {
    condition     = length(var.drift_resource_type_scopes) > 0
    error_message = "drift_resource_type_scopes must list at least one resource type to scan."
  }

  validation {
    condition = alltrue([
      for keys in values(var.drift_resource_type_scopes) : length(keys) >= 1
    ])
    error_message = "Each resource type must list at least one required tag key."
  }
}

# Optional explicit name for the drift report bucket. Defaults to a
# deterministic, account-scoped name when null.
variable "drift_report_bucket_name" {
  description = "Name of the S3 bucket for drift reports. Null derives a deterministic account-scoped name."
  type        = string
  default     = null

  validation {
    condition     = var.drift_report_bucket_name == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", coalesce(var.drift_report_bucket_name, "placeholder-bucket")))
    error_message = "drift_report_bucket_name must be a valid S3 bucket name or null."
  }
}

# Retention for stored drift reports before expiration.
variable "drift_report_retention_days" {
  description = "Days to retain drift report objects before expiration."
  type        = number
  default     = 365

  validation {
    condition     = var.drift_report_retention_days >= 1 && var.drift_report_retention_days <= 3650
    error_message = "drift_report_retention_days must be between 1 and 3650."
  }
}

# Schedule for the drift scan. Defaults to a weekly Monday-morning run.
variable "drift_report_schedule_expression" {
  description = "EventBridge schedule expression controlling how often the drift report runs."
  type        = string
  default     = "cron(0 7 ? * MON *)"

  validation {
    condition     = can(regex("^(rate\\(.+\\)|cron\\(.+\\))$", var.drift_report_schedule_expression))
    error_message = "drift_report_schedule_expression must be a rate(...) or cron(...) expression."
  }
}

# Optional email addresses subscribed to the drift notification topic.
variable "drift_report_email_addresses" {
  description = "Email addresses subscribed to the drift notification topic."
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for e in var.drift_report_email_addresses : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))
    ])
    error_message = "Each entry must be a valid email address."
  }
}

# Maximum number of drifted resources enumerated inline in the SNS summary; the
# full detail always lives in the S3 report.
variable "drift_summary_limit" {
  description = "Maximum drifted resources listed inline in the drift notification."
  type        = number
  default     = 50

  validation {
    condition     = var.drift_summary_limit >= 1 && var.drift_summary_limit <= 500
    error_message = "drift_summary_limit must be between 1 and 500."
  }
}
