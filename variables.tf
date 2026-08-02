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
