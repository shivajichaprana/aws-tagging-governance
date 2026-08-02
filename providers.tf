# Tag governance is an organization-wide control plane. Organizations tag
# policies are created and attached from the management account (or a
# delegated administrator for the Organizations policy service). Point this
# provider at that account before applying.
provider "aws" {
  region = var.aws_region

  # Baseline governance tags applied to every resource this configuration
  # manages (the policies and any supporting resources), so the tooling that
  # enforces tagging is itself consistently tagged.
  default_tags {
    tags = var.default_tags
  }
}
