# Tag governance — common operations.
# Run `make help` for the target list.

TF            ?= terraform
PYTHON        ?= python3
TFLINT_ARGS   ?= --minimum-failure-severity=error
FLAKE8_SELECT ?= E9,F63,F7,F82

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: init
init: ## Initialize Terraform without a backend
	$(TF) init -backend=false -input=false

.PHONY: fmt
fmt: ## Format Terraform files in place
	$(TF) fmt -recursive

.PHONY: fmt-check
fmt-check: ## Check Terraform formatting (CI parity)
	$(TF) fmt -check -diff -recursive

.PHONY: validate
validate: fmt-check init ## Run the full local check set (fmt, validate, lint, tests)
	$(TF) validate
	$(MAKE) lint
	$(MAKE) test

.PHONY: lint
lint: ## Lint Terraform (TFLint) and Python (flake8)
	tflint --init
	tflint $(TFLINT_ARGS)
	flake8 --select=$(FLAKE8_SELECT) $$(git ls-files '*.py')
	$(PYTHON) -m py_compile $$(git ls-files '*.py')

.PHONY: test
test: ## Run the Python unit tests
	$(PYTHON) -m pytest tests/ -q

.PHONY: plan
plan: init ## Show the Terraform plan
	$(TF) plan

.PHONY: deploy
deploy: ## Apply the governance stack (review the plan first)
	$(TF) apply

.PHONY: policy
policy: ## Print the rendered tag policy document for review
	$(TF) output -raw tag_policy_document

.PHONY: scan
scan: ## Invoke the drift reporter on demand
	@fn=$$($(TF) output -raw tag_drift_reporter_function_name); \
	echo "Invoking drift reporter: $$fn"; \
	aws lambda invoke --function-name "$$fn" /dev/stdout

.PHONY: destroy
destroy: ## Destroy the governance stack
	$(TF) destroy

.PHONY: clean
clean: ## Remove local Terraform state cache and plan artifacts
	rm -rf .terraform .terraform.lock.hcl tfplan
