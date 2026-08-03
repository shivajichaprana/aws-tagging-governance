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
