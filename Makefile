BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
BUILD_DIR=./bin
VERSION?=dev
LDFLAGS=-ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=$(VERSION)"

.PHONY: build build-cli build-server install install-cli install-server clean run dev docker-build docker-up docker-down docker-logs

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

run:
	KEYORIX_DB_PASSWORD=testpassword123 go run server/main.go

dev: install-cli
	@echo "✓ keyorix CLI installed to /usr/local/bin"
	@echo "✓ Start server with: make run"

clean:
	rm -rf $(BUILD_DIR)

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
