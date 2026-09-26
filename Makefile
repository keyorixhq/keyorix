BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
# The old, thick CLI (internal/cli, root `.` package) is no longer a release asset
# (Phase 5 switch, ADR-108) -- kept in the tree, unbuilt by default, for one release as
# a rollback and for scripts/cli-parity-check.sh / scripts/smoke-legacy.sh. Removed
# entirely in Phase 6 alongside internal/storage/store's RemoteStorage and /system.
BINARY_CLI_LEGACY=keyorix-legacy
# Lightweight/air-gapped release variant (-tags lean): drops
# aws-sdk-go-v2/service/{iam,s3} (see internal/rotation/awsiam_lean.go,
# internal/evidencesink/objectstore_lean.go) for installs that don't use the
# AWS IAM rotation backend or the S3-compatible evidence sink. Linux only —
# this variant targets air-gapped production servers, not local dev on macOS.
BINARY_SERVER_LEAN=$(BINARY_SERVER)-lean
BUILD_DIR=./bin
VERSION?=dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Air-gap trust keys (ADR-062): embed the trusted update/license signing PUBLIC keys at
# build time, each "keyID=base64pub". Empty by default → a dev build trusts no keys and
# verification fails closed; release builds set these. `keyorix trust keygen` prints the
# exact value to use.
TRUST_UPDATE_KEYS?=
TRUST_LICENSE_KEYS?=
# Inject the build identity into keyorix-server plus the shared internal/version package
# (read by the server's /health + /system/info) and the legacy CLI (internal/cli.version,
# keyorix-legacy only -- the new CLI is a separate module with its own ldflags below).
# Commit is deterministic per source revision, so release builds stay reproducible (no
# build date).
VERSION_LDFLAGS=-X github.com/keyorixhq/keyorix/internal/cli.version=$(VERSION) -X github.com/keyorixhq/keyorix/internal/version.Version=$(VERSION) -X github.com/keyorixhq/keyorix/internal/version.Commit=$(GIT_COMMIT) -X github.com/keyorixhq/keyorix/pkg/trust.updateKeysB64=$(TRUST_UPDATE_KEYS) -X github.com/keyorixhq/keyorix/pkg/trust.licenseKeysB64=$(TRUST_LICENSE_KEYS)
LDFLAGS=-ldflags "$(VERSION_LDFLAGS)"
# RELEASE_LDFLAGS additionally strips the symbol table + DWARF debug info (-s -w):
# ~92MB -> ~62MB for keyorix-server. Only the `release` target uses this — build-cli/
# build-server/build-ui/dev keep full symbols (plain LDFLAGS) for local debugging.
# Stripping does NOT remove pclntab, so panic stack traces still show function names;
# only an attached debugger (dlv) loses symbols, an acceptable release-binary tradeoff.
RELEASE_LDFLAGS=-ldflags "-s -w $(VERSION_LDFLAGS)"
# The new CLI (cli/) is a separate Go module (ADR-108 Decision A) with its own build
# identity package, cli/internal/cliversion -- it cannot see internal/cli.version or
# internal/version, and must not: importing either would violate the no-server-deps
# guarantee cli/internal/depguard enforces. No commit/trust keys: the thin CLI has no
# air-gap update/license verification surface of its own.
CLI_VERSION_LDFLAGS=-X github.com/keyorixhq/keyorix/cli/internal/cliversion.Version=$(VERSION)
CLI_LDFLAGS=-ldflags "$(CLI_VERSION_LDFLAGS)"
CLI_RELEASE_LDFLAGS=-ldflags "-s -w $(CLI_VERSION_LDFLAGS)"

.PHONY: build build-cli build-server build-ui populate-webui-dist install install-cli install-server clean run db-up dev docker-build docker-up docker-down docker-logs proto proto-deps proto-lint release sbom _sbom-generate smoke keyorix-legacy smoke-legacy check-release-assets airgap-e2e

# Pinned protoc-gen plugin versions (match google.golang.org/{protobuf,grpc} in go.mod).
PROTOC_GEN_GO_VERSION=v1.36.11
PROTOC_GEN_GO_GRPC_VERSION=v1.6.2

# Install the protoc-gen-go / protoc-gen-go-grpc plugins buf invokes. buf itself
# must be installed separately (`brew install bufbuild/buf/buf`).
proto-deps:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto-lint:
	buf lint

# Regenerate server/proto/pb/*.pb.go from server/proto/keyorix.proto. Runs
# proto-deps first so a fresh checkout works; needs the Go bin dir on PATH.
#
# The rm is what buf.gen.yaml's `clean:` used to do, narrowed to the files
# this target actually owns. buf's own clean wipes the whole output directory,
# which meant every `make proto` deleted server/proto/pb/generated_code_test.go
# -- the hand-written guard asserting this package contains only generated
# code. See buf.gen.yaml for the full note.
proto: proto-deps
	rm -f server/proto/pb/*.pb.go
	PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

build: build-cli build-server

# The new, thin CLI (cli/) is a separate Go module excluded from the repo's root
# go.work (matching operator/'s precedent -- see cli/Makefile's own header), so
# building it from here requires cd'ing in with GOWORK=off, same as every other
# cli/-targeting recipe below (release, _sbom-generate).
build-cli:
	(cd cli && GOWORK=off go build $(CLI_LDFLAGS) -o $(CURDIR)/$(BUILD_DIR)/$(BINARY_CLI) .)

build-server:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server

# keyorix-legacy: the old, thick CLI (internal/cli, root `.` package), built under a
# distinct name so it can never collide with or accidentally ship as $(BINARY_CLI).
# Dev-only -- not part of `build`, `install`, or `release`. Exists for
# scripts/smoke-legacy.sh, scripts/cli-parity-check.sh, and as the rollback path for
# one release (Phase 5, ADR-108) until Phase 6 deletes internal/cli entirely.
keyorix-legacy:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI_LEGACY) .

# populate-webui-dist: builds the dashboard (web/, now an in-repo subtree —
# ADR-070) and copies the real output into server/webui/dist/, which is
# gitignored except the committed placeholder index.html. Does NOT restore
# that placeholder — shared by build-ui and release below, which each need
# the real dist/ present for one or more `go build`s (embed.go's
# `//go:embed all:dist` bakes in whatever is physically on disk at compile
# time) and each restore the placeholder themselves, exactly once, after
# their own last build that needs the real thing. Restoring here instead
# would run in the middle of release's 10 cross-compiles (Make prerequisites
# complete in full before the depending target's own recipe starts), leaving
# every one of them with a placeholder index.html paired with the real
# hashed JS/CSS bundles copied in below -- a broken, inconsistent embed.
populate-webui-dist:
	@command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI"; exit 1; }
	cd web && pnpm install --frozen-lockfile && pnpm build
	rm -rf server/webui/dist
	mkdir -p server/webui/dist
	cp -R web/dist/. server/webui/dist/

# build-ui: build the web dashboard and embed it into a native server binary,
# so a single keyorix-server serves both API and UI (air-gap "one file"
# deploy). Requires pnpm. The committed placeholder is restored afterward so
# the working tree stays clean — the binary already has the real UI embedded
# regardless of what's on disk after this returns.
build-ui: populate-webui-dist
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server
	@git checkout -- server/webui/dist/index.html 2>/dev/null || true
	@echo "Built $(BUILD_DIR)/$(BINARY_SERVER) with the web UI embedded."

install-cli: build-cli
	sudo mv $(BUILD_DIR)/$(BINARY_CLI) /usr/local/bin/$(BINARY_CLI)

install-server: build-server
	sudo mv $(BUILD_DIR)/$(BINARY_SERVER) /usr/local/bin/$(BINARY_SERVER)

install: install-cli install-server

# Run the server locally against the docker-compose Postgres, using the
# committed dev config. `db-up` ensures Postgres is running first.
run: db-up
	KEYORIX_CONFIG_PATH=configs/dev.yaml KEYORIX_DB_PASSWORD=keyorix123 KEYORIX_MASTER_PASSWORD=keyorix123 go run ./server

# Start only the Postgres service (not the full stack — `make run` runs the
# server on :8080 itself, so we don't want the compose server container too).
db-up:
	docker compose up -d postgres

dev: install-cli
	@echo "✓ keyorix CLI installed to /usr/local/bin"
	@echo "✓ Start server with: make run"

# Cross-compile the published release artifacts. Asset names use the
# {binary}_{os}_{arch} convention that install.sh downloads and that the GitHub
# releases already use — keep these three in sync. Consumed by
# .github/workflows/release.yml on a vX.Y.Z tag.
#
# Depends on populate-webui-dist, not build-ui: build-ui's own recipe ends by
# restoring server/webui/dist/index.html to the committed placeholder, and
# Make prerequisites run to completion before this recipe starts — depending
# on build-ui here would mean every one of the 10 `go build`s below embeds a
# placeholder index.html alongside the real hashed JS/CSS bundles
# populate-webui-dist copies in, since nothing would rebuild dist/ in
# between. The 6 server-family builds (4 full + 2 lean) are the ones that
# actually embed it (server/webui/embed.go), but populating once up front is
# simplest and harmless for the 4 CLI builds. The placeholder is restored
# once, at the very end, after every build that needs the real dist/ has
# already run.
release: populate-webui-dist
	@echo "→ Cross-compiling $(VERSION)"
	@mkdir -p dist
	(cd cli && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_linux_amd64    .)
	(cd cli && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_linux_arm64    .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_darwin_amd64   .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(CLI_RELEASE_LDFLAGS) -trimpath -o $(CURDIR)/dist/$(BINARY_CLI)_darwin_arm64   .)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_amd64  ./server
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_arm64  ./server
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_amd64 ./server
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_arm64 ./server
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build -tags lean $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER_LEAN)_linux_amd64 ./server
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build -tags lean $(RELEASE_LDFLAGS) -trimpath -o dist/$(BINARY_SERVER_LEAN)_linux_arm64 ./server
	$(MAKE) _sbom-generate
	@cd dist && (sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt)
	@git checkout -- server/webui/dist/index.html 2>/dev/null || true
	$(MAKE) check-release-assets
	@echo "✅ Release binaries + SBOMs in dist/"

# check-release-assets: the legacy CLI (keyorix-legacy) must NEVER be a release asset
# (Phase 5, ADR-108 -- rollback is `make keyorix-legacy` from source, not a downloadable
# binary). Derived from the actual dist/ output, not from re-reading this recipe's own
# text, so a future line added here that (accidentally or not) emits a legacy-named
# asset is caught by what it PRODUCES, not by trusting the recipe that produced it.
check-release-assets:
	@echo "→ Verifying dist/ contains no legacy-CLI asset"
	@legacy="$$(ls dist/ 2>/dev/null | grep -i '$(BINARY_CLI_LEGACY)' || true)"; \
	if [ -n "$$legacy" ]; then \
		echo "release asset list contains a legacy-CLI binary, which must never ship:"; \
		echo "$$legacy"; \
		exit 1; \
	fi
	@echo "✅ No legacy-CLI asset in dist/"

# CycloneDX SBOM per shipped binary (app mode: exactly the deps linked into that
# binary + Go stdlib) plus one production-only frontend SBOM linked from each
# server binary's SBOM (ADR-073 — before that ADR, this covered the Go module
# graph only, which stopped being a complete description of keyorix-server the
# moment server/webui/embed.go started baking the built dashboard in). Feed to
# govulncheck/grype to answer "are we affected by CVE-X?" — the core CRA
# Article 14 question. Requires cyclonedx-gomod on PATH
# (go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0)
# and cdxgen on PATH (npm ci --ignore-scripts, then add
# node_modules/.bin to PATH — see package.json).
sbom:
	@mkdir -p dist
	$(MAKE) _sbom-generate
	@echo "✅ SBOMs in dist/"

# Shared by release and sbom so the two targets can't silently drift (ADR-073).
# Order matters and is enforced by this sequencing, not left to convention:
# the frontend SBOM must exist in its final form, hashed, before any server
# Go SBOM is generated and linked to it — generating them the other way
# round would leave a reference that validates cleanly while pointing at a
# stale or absent hash. See scripts/link-sbom.mjs's own header.
_sbom-generate:
	@echo "→ Generating frontend SBOM (ADR-073), production scope only"
	# cdxgen must run with NO --type flag here. `--type npm` silently drops to
	# scanning package.json's direct dependencies only (47 components instead
	# of the real ~478-package pnpm-lock.yaml graph filtered to ~125
	# production) — no error, just wrong. See
	# web/scripts/build-frontend-sbom.mjs's own header for the full story
	# (this exact trap, measured, is why the flag is absent below).
	cd web && node scripts/build-frontend-sbom.mjs ../dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	@echo "→ Generating per-binary Go CycloneDX SBOMs (one per binary, not per binary family)"
	(cd cli && GOWORK=off GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_linux_amd64_sbom.cdx.json    .)
	(cd cli && GOWORK=off GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_linux_arm64_sbom.cdx.json    .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_darwin_amd64_sbom.cdx.json   .)
	(cd cli && GOWORK=off GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main . -licenses -output $(CURDIR)/dist/$(BINARY_CLI)_darwin_arm64_sbom.cdx.json   .)
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json  .
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json  .
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json .
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json .
	@echo "→ Generating per-binary Go CycloneDX SBOMs for the lean release variant"
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-tags=lean cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER_LEAN)_linux_amd64_sbom.cdx.json .
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 GOFLAGS=-tags=lean cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER_LEAN)_linux_arm64_sbom.cdx.json .
	@echo "→ Linking frontend SBOM into the six server Go SBOMs (ADR-073)"
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json  dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json  dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER_LEAN)_linux_amd64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	node scripts/link-sbom.mjs dist/$(BINARY_SERVER_LEAN)_linux_arm64_sbom.cdx.json dist/$(BINARY_SERVER)_frontend_sbom.cdx.json
	@echo "→ Verifying frontend SBOM hash matches all six server SBOM links (ADR-073 decision #5)"
	node scripts/verify-sbom-links.mjs \
		dist/$(BINARY_SERVER)_frontend_sbom.cdx.json \
		dist/$(BINARY_SERVER)_linux_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_linux_arm64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_darwin_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER)_darwin_arm64_sbom.cdx.json \
		dist/$(BINARY_SERVER_LEAN)_linux_amd64_sbom.cdx.json \
		dist/$(BINARY_SERVER_LEAN)_linux_arm64_sbom.cdx.json

# smoke: the CI + release gate for the SHIPPED $(BINARY_CLI) binary (Phase 5, ADR-108).
# Executes the documented QUICK_START.md flow -- keyorix-server admin init, start the
# server, keyorix login, project create, secret create/get, secret export -- step for
# step against a freshly built binary. See scripts/smoke.sh's own header for the exact
# correspondence to QUICK_START.md.
smoke: build-cli build-server
	@./scripts/smoke.sh

# smoke-legacy: the OLD CLI's embedded-mode flow (system init, no --server, direct DB
# access), moved out of `smoke` by the Phase 5 switch since the new CLI has no embedded
# mode at all. Dev/CI-only, never a release gate -- kept until Phase 6 deletes
# internal/cli. See scripts/smoke-legacy.sh's own header.
smoke-legacy: keyorix-legacy
	@./scripts/smoke-legacy.sh

# airgap-e2e: MANUAL target only, not run in CI (needs Docker/Podman, spins up
# real containers, takes tens of seconds waiting out a real audit-checkpoint
# interval) -- see scripts/airgap-e2e.sh's own header for the full flow and
# why CI's unit/integration/fuzz layer (server/admin/backup_restore_*_test.go)
# isn't a substitute for it.
airgap-e2e:
	@./scripts/airgap-e2e.sh

clean:
	rm -rf $(BUILD_DIR) dist/

docker-build:
	docker build -f server/Dockerfile -t keyorix-server .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f keyorix
vet:
	go vet ./...
lint:
	golangci-lint run ./...
test:
	go test -race ./...
test-cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
security:
	govulncheck ./...
	gosec ./...
ci: vet test security build
