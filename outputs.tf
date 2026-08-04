output "tag_policy_id" {
  description = "ID of the Organizations tag policy."
  value       = aws_organizations_policy.required_tags.id
}

output "tag_policy_arn" {
  description = "ARN of the Organizations tag policy."
  value       = aws_organizations_policy.required_tags.arn
}

output "tag_policy_document" {
  description = "Rendered tag policy JSON document, for review before attachment."
  value       = local.tag_policy_document
}

output "tag_policy_attachment_target_ids" {
  description = "Organization targets the tag policy is attached to."
  value       = [for a in aws_organizations_policy_attachment.required_tags : a.target_id]
}

output "required_tag_keys" {
  description = "Tag keys standardized by this policy."
  value       = keys(var.required_tags)
}

output "config_rule_names" {
  description = "Map of AWS Config resource type to the REQUIRED_TAGS rule name created for it."
  value       = { for rtype, rule in aws_config_config_rule.required_tags : rtype => rule.name }
}

output "config_rule_arns" {
  description = "Map of AWS Config resource type to the ARN of the REQUIRED_TAGS rule created for it."
  value       = { for rtype, rule in aws_config_config_rule.required_tags : rtype => rule.arn }
}

output "config_recorder_name" {
  description = "Name of the AWS Config recorder, when this configuration manages one."
  value       = one(aws_config_configuration_recorder.this[*].name)
}

output "config_delivery_bucket" {
  description = "Name of the Config delivery bucket, when this configuration manages the recorder."
  value       = one(aws_s3_bucket.config[*].id)
}

output "tag_remediator_function_name" {
  description = "Name of the tag remediation function, when the remediation layer is enabled."
  value       = one(aws_lambda_function.tag_remediator[*].function_name)
}

output "tag_remediator_function_arn" {
  description = "ARN of the tag remediation function, when the remediation layer is enabled."
  value       = one(aws_lambda_function.tag_remediator[*].arn)
}

output "remediation_topic_arn" {
  description = "ARN of the remediation notification topic, when the remediation layer is enabled."
  value       = one(aws_sns_topic.remediation[*].arn)
}

output "remediation_kms_key_arn" {
  description = "ARN of the KMS key encrypting the remediation log group and topic."
  value       = one(aws_kms_key.remediation[*].arn)
}

output "ssm_remediation_document_name" {
  description = "Name of the SSM Automation document that invokes tag remediation."
  value       = one(aws_ssm_document.tag_remediation[*].name)
}

output "ssm_automation_role_arn" {
  description = "ARN of the role Systems Manager Automation assumes to run the remediation runbook."
  value       = one(aws_iam_role.ssm_automation[*].arn)
}

output "config_remediation_rule_names" {
  description = "Config rules wired to the remediation document, when Config remediation is enabled."
  value       = [for r in aws_config_remediation_configuration.tag_remediation : r.config_rule_name]
}
