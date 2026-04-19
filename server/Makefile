# Keyorix Server Makefile

# Variables
BINARY_NAME=keyorix-server
PROTO_DIR=proto
PROTO_FILES=$(wildcard $(PROTO_DIR)/*.proto)
PB_DIR=$(PROTO_DIR)/pb
GO_FILES=$(shell find . -name "*.go" -type f)

# Build info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.gitCommit=$(GIT_COMMIT)"

.PHONY: all build clean test proto deps run dev help

# Default target
all: deps proto build

# Build the server binary
build: $(BINARY_NAME)

$(BINARY_NAME): $(GO_FILES)
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o $(BINARY_NAME) ./main.go

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Generate protobuf files
proto: $(PB_DIR)
	@echo "Generating protobuf files..."
	protoc --go_out=$(PB_DIR) --go_opt=paths=source_relative \
		--go-grpc_out=$(PB_DIR) --go-grpc_opt=paths=source_relative \
		$(PROTO_FILES)

$(PB_DIR):
	mkdir -p $(PB_DIR)

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run the server in development mode
dev: build
	@echo "Starting server in development mode..."
	./$(BINARY_NAME)

# Run the server
run: build
	@echo "Starting server..."
	./$(BINARY_NAME)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html
	rm -rf $(PB_DIR)

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Generate TLS certificates for development
certs:
	@echo "Generating development TLS certificates..."
	mkdir -p certs
	openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
		-days 365 -nodes -subj "/C=US/ST=CA/L=SF/O=Keyorix/CN=localhost"

# Docker build
docker-build:
	@echo "Building Docker image..."
	docker build -t keyorix-server:$(VERSION) .

# Docker run
docker-run: docker-build
	@echo "Running Docker container..."
	docker run -p 8080:8080 -p 9090:9090 keyorix-server:$(VERSION)

# Show help
help:
	@echo "Available targets:"
	@echo "  all           - Install deps, generate proto, and build"
	@echo "  build         - Build the server binary"
	@echo "  deps          - Install Go dependencies"
	@echo "  proto         - Generate protobuf files"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  dev           - Run server in development mode"
	@echo "  run           - Run the server"
	@echo "  clean         - Clean build artifacts"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  certs         - Generate development TLS certificates"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help message"