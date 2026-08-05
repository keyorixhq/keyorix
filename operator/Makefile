# Makefile for the Keyorix operator (a separate Go module from the repo root).
# All Go commands run with GOWORK=off so this module resolves independently.

# Pinned, not @latest: an unpinned `go run ...@latest` here is exactly the
# same class of gap as an unpinned CI action -- a code-generation tool that
# can silently change its output between runs with no gate in front of it.
# This isn't hypothetical: an unpinned controller-gen run against this exact
# repo once regenerated role.yaml and, in doing so, silently discarded a
# hand-written explanatory comment that lived in the generated file at the
# time (controller-gen's rbac generator does not preserve hand-written
# content in its output -- confirmed directly, not assumed -- which is also
# why that explanation now lives in operator/internal/controller/
# keyorixsecret_controller.go next to the +kubebuilder:rbac markers instead
# of in role.yaml itself). Bump deliberately, the same way GOSEC_VERSION /
# GOLANGCI_LINT_VERSION / etc. are pinned in the root ci.yml.
CONTROLLER_TOOLS_VERSION ?= v0.21.0
CONTROLLER_GEN ?= go run sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)
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
