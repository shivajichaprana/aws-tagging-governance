# Builds an AWS Organizations tag policy document from the declarative
# required_tags variable and attaches it to the chosen organization targets.
#
# A tag policy defines the tag keys the organization standardizes on, the
# allowed values for those keys, and (optionally) the resource types on which a
# non-compliant value is blocked at tag-modification time. It is a preventive,
# organization-wide control that complements the detective AWS Config rules and
# the remediation workflow that live alongside it.

locals {
  # Translate each required tag into the tag-policy schema. tag_value and
  # enforced_for are only emitted when configured, so a key that only needs to
  # be standardized (without value restrictions) produces a minimal, valid
  # statement rather than empty assignment blocks.
  tag_policy_statements = {
    for key, cfg in var.required_tags : key => merge(
      {
        tag_key = {
          "@@assign" = key
        }
      },
      length(cfg.allowed_values) > 0 ? {
        tag_value = {
          "@@assign" = cfg.allowed_values
        }
      } : {},
      length(cfg.enforced_for) > 0 ? {
        enforced_for = {
          "@@assign" = cfg.enforced_for
        }
      } : {},
    )
  }

  tag_policy_document = jsonencode({
    tags = local.tag_policy_statements
  })
}

resource "aws_organizations_policy" "required_tags" {
  name        = "${var.name_prefix}-required-tags"
  description = "Organization tag policy standardizing required tag keys, allowed values, and enforced resource types."
  type        = "TAG_POLICY"
  content     = local.tag_policy_document

  tags = merge(var.default_tags, {
    Name = "${var.name_prefix}-required-tags"
  })

  lifecycle {
    precondition {
      condition     = length(var.required_tags) > 0
      error_message = "At least one required tag must be defined to create a tag policy."
    }
  }
}

# Attach the policy to each requested target. With an empty policy_target_ids
# the policy is created but left unattached, supporting a review-first rollout
# where the document is inspected before it takes effect anywhere.
resource "aws_organizations_policy_attachment" "required_tags" {
  for_each = toset(var.policy_target_ids)

  policy_id = aws_organizations_policy.required_tags.id
  target_id = each.value
}
