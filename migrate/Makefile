# migrate/Makefile -- keyorix-migrate's own module (ADR-108's "moved out, not dropped"
# decision, docs/design-keyorix-migrate.md). Mirrors cli/Makefile's shape deliberately: same
# generated-client approach, same reason for a separate module (a separate release cadence
# and a separate SBOM -- this one DOES carry cloud SDKs, cli/ never does).

OAPI_CODEGEN_VERSION=v2.4.1
FILTERED_SPEC=$(CURDIR)/.openapi-filtered.yaml

# Deliberately excluded from the repo's root go.work, same as cli/ and operator/ -- see
# cli/Makefile's comment for why this matters when invoked from a subdirectory.
export GOWORK=off

.PHONY: build migrate-vault-only test client-deps client

build:
	go build -o bin/keyorix-migrate .

# Vault-only build: excludes the AWS/Azure/GCP cloud sources (and their SDKs) via build tags --
# for an air-gapped or Vault-only install that has no use for any cloud SDK's SBOM weight. See
# docs/migrate-from-cloud.md's size table for what each provider costs; this target drops all
# three, landing back at the pre-cloud-sources ~10MB binary size.
migrate-vault-only:
	go build -tags nomigrate_aws,nomigrate_azure,nomigrate_gcp -o bin/keyorix-migrate-vault-only .

test:
	go test ./...

client-deps:
	go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION)

# Regenerate internal/apiclient/{types,client}.gen.go from the server's own
# server/http/handlers/openapi.yaml, narrowed to the paths this module actually calls
# (internal/apiclient/gen/filterspec.go's keptPaths list). This is migrate's OWN generation
# pass -- it does not import cli/internal/apiclient (cli/ is not a dependency-safe leaf; see
# docs/design-keyorix-migrate.md's "Module boundaries" section).
client: client-deps
	go run ./internal/apiclient/gen ../server/http/handlers/openapi.yaml $(FILTERED_SPEC)
	PATH="$$(go env GOPATH)/bin:$$PATH" oapi-codegen -generate types -package apiclient -o internal/apiclient/types.gen.go $(FILTERED_SPEC)
	PATH="$$(go env GOPATH)/bin:$$PATH" oapi-codegen -generate client -package apiclient -o internal/apiclient/client.gen.go $(FILTERED_SPEC)
	rm -f $(FILTERED_SPEC)
