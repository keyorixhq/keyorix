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

.PHONY: build build-cli build-server build-ui install install-cli install-server clean run db-up dev docker-build docker-up docker-down docker-logs proto proto-deps proto-lint release

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

# Path to the keyorix-web checkout (override: make build-ui KEYORIX_WEB_DIR=/path).
KEYORIX_WEB_DIR ?= ../keyorix-web

# build-ui: build the web dashboard and embed it into the server binary, so a
# single keyorix-server serves both API and UI (air-gap "one file" deploy).
# Requires pnpm + a keyorix-web checkout at KEYORIX_WEB_DIR. The committed
# placeholder is restored afterward so the working tree stays clean — the binary
# already has the real UI embedded.
build-ui:
	@command -v pnpm >/dev/null 2>&1 || { echo "pnpm is required to build the web UI"; exit 1; }
	@test -d "$(KEYORIX_WEB_DIR)" || { echo "keyorix-web not found at $(KEYORIX_WEB_DIR); set KEYORIX_WEB_DIR=<path>"; exit 1; }
	cd "$(KEYORIX_WEB_DIR)" && pnpm install --frozen-lockfile && pnpm build
	rm -rf server/webui/dist
	mkdir -p server/webui/dist
	cp -R "$(KEYORIX_WEB_DIR)"/dist/. server/webui/dist/
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
release:
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
	@cd dist && (sha256sum * > checksums.txt 2>/dev/null || shasum -a 256 * > checksums.txt)
	@echo "✅ Release binaries in dist/"

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
