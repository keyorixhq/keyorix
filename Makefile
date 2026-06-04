BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
BUILD_DIR=./bin
VERSION?=dev
LDFLAGS=-ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=$(VERSION)"

.PHONY: build build-cli build-server install install-cli install-server clean run db-up dev docker-build docker-up docker-down docker-logs

build: build-cli build-server

build-cli:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) .

build-server:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SERVER) ./server/main.go

install-cli: build-cli
	sudo mv $(BUILD_DIR)/$(BINARY_CLI) /usr/local/bin/$(BINARY_CLI)

install-server: build-server
	sudo mv $(BUILD_DIR)/$(BINARY_SERVER) /usr/local/bin/$(BINARY_SERVER)

install: install-cli install-server

# Run the server locally against the docker-compose Postgres, using the
# committed dev config. `db-up` ensures Postgres is running first.
run: db-up
	KEYORIX_CONFIG_PATH=configs/dev.yaml KEYORIX_DB_PASSWORD=keyorix123 KEYORIX_MASTER_PASSWORD=keyorix123 go run server/main.go

# Start only the Postgres service (not the full stack — `make run` runs the
# server on :8080 itself, so we don't want the compose server container too).
db-up:
	docker compose up -d postgres

dev: install-cli
	@echo "✓ keyorix CLI installed to /usr/local/bin"
	@echo "✓ Start server with: make run"

release:
	@echo "→ Cross-compiling $(VERSION)"
	@mkdir -p dist
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)-linux-amd64   .
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)-linux-arm64   .
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)-darwin-amd64  .
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_CLI)-darwin-arm64  .
	GOOS=linux  GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)-linux-amd64  ./server/main.go
	GOOS=linux  GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)-linux-arm64  ./server/main.go
	GOOS=darwin GOARCH=amd64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)-darwin-amd64 ./server/main.go
	GOOS=darwin GOARCH=arm64  CGO_ENABLED=0 go build $(LDFLAGS) -trimpath -o dist/$(BINARY_SERVER)-darwin-arm64 ./server/main.go
	@cd dist && sha256sum * > checksums.txt
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
