BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
BUILD_DIR=./bin
VERSION?=dev
GIT_COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Air-gap trust keys (ADR-062): embed the trusted update/license signing PUBLIC keys at
# build time, each "keyID=base64pub". Empty by default → a dev build trusts no keys and
# verification fails closed; release builds set these. `keyorix trust keygen` prints the
# exact value to use.
TRUST_UPDATE_KEYS?=
TRUST_LICENSE_KEYS?=
# Inject the build identity into both the CLI (internal/cli.version) and the shared
# internal/version package (read by the server's /health + /system/info). Commit is
# deterministic per source revision, so release builds stay reproducible (no build date).
LDFLAGS=-ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=$(VERSION) -X github.com/keyorixhq/keyorix/internal/version.Version=$(VERSION) -X github.com/keyorixhq/keyorix/internal/version.Commit=$(GIT_COMMIT) -X github.com/keyorixhq/keyorix/internal/trust.updateKeysB64=$(TRUST_UPDATE_KEYS) -X github.com/keyorixhq/keyorix/internal/trust.licenseKeysB64=$(TRUST_LICENSE_KEYS)"

.PHONY: build build-cli build-server build-ui populate-webui-dist install install-cli install-server clean run db-up dev docker-build docker-up docker-down docker-logs proto proto-deps proto-lint release sbom

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
proto: proto-deps
	PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

build: build-cli build-server

build-cli:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) .

build-server:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server

# populate-webui-dist: builds the dashboard (web/, now an in-repo subtree —
# ADR-070) and copies the real output into server/webui/dist/, which is
# gitignored except the committed placeholder index.html. Does NOT restore
# that placeholder — shared by build-ui and release below, which each need
# the real dist/ present for one or more `go build`s (embed.go's
# `//go:embed all:dist` bakes in whatever is physically on disk at compile
# time) and each restore the placeholder themselves, exactly once, after
# their own last build that needs the real thing. Restoring here instead
# would run in the middle of release's 8 cross-compiles (Make prerequisites
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
# on build-ui here would mean every one of the 8 `go build`s below embeds a
# placeholder index.html alongside the real hashed JS/CSS bundles
# populate-webui-dist copies in, since nothing would rebuild dist/ in
# between. The 4 server (not CLI) builds are the ones that actually embed
# it (server/webui/embed.go), but populating once up front is simplest and
# harmless for the 4 CLI builds. The placeholder is restored once, at the
# very end, after every build that needs the real dist/ has already run.
release: populate-webui-dist
	@echo "→ Cross-compiling $(VERSION)"
	@mkdir -p dist
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)_linux_amd64    .
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)_linux_arm64    .
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)_darwin_amd64   .
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)_darwin_arm64   .
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_amd64  ./server
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_linux_arm64  ./server
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_amd64 ./server
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)_darwin_arm64 ./server
	@echo "→ Generating CycloneDX SBOMs (per binary, app mode)"
	cyclonedx-gomod app -json -main .      -licenses -output dist/$(BINARY_CLI)_sbom.cdx.json    .
	cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_sbom.cdx.json .
	@cd dist && (sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt)
	@git checkout -- server/webui/dist/index.html 2>/dev/null || true
	@echo "✅ Release binaries + SBOMs in dist/"

# CycloneDX SBOM per shipped binary (app mode: exactly the deps linked into that
# binary + Go stdlib). Feed to govulncheck/grype to answer "are we affected by
# CVE-X?" — the core CRA Article 14 question. Requires cyclonedx-gomod on PATH
# (go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@v1.10.0).
sbom:
	@mkdir -p dist
	cyclonedx-gomod app -json -main .      -licenses -output dist/$(BINARY_CLI)_sbom.cdx.json    .
	cyclonedx-gomod app -json -main server -licenses -output dist/$(BINARY_SERVER)_sbom.cdx.json .
	@echo "✅ SBOMs in dist/"

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
