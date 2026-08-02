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
