# Makefile for the Keyorix operator (a separate Go module from the repo root).
# All Go commands run with GOWORK=off so this module resolves independently.

CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@latest
GO ?= GOWORK=off go

CHART_CRD_DIR ?= ../deploy/helm/keyorix-operator/crds

.PHONY: all
all: generate manifests build test

.PHONY: generate
generate: ## Generate DeepCopy methods.
	$(CONTROLLER_GEN) object paths=./api/...

.PHONY: manifests
manifests: ## Generate the CRD + RBAC, and sync the CRD into the Helm chart.
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=./config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=keyorix-operator paths=./internal/controller/... output:rbac:dir=./config/rbac
	cp config/crd/bases/secrets.keyorix.io_keyorixsecrets.yaml $(CHART_CRD_DIR)/

.PHONY: build
build: ## Build the manager binary.
	$(GO) build -o bin/keyorix-operator ./cmd

.PHONY: test
test: ## Run unit/controller tests (fake client; no envtest required).
	$(GO) test ./...

.PHONY: lint
lint: ## Vet + gofmt check.
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)

.PHONY: docker-build
docker-build: ## Build the operator image (context = this dir).
	docker build -t ghcr.io/keyorixhq/keyorix-operator:dev .
