BINARY_CLI=keyorix
BINARY_SERVER=keyorix-server
BUILD_DIR=./bin
VERSION?=dev
LDFLAGS=-ldflags "-X github.com/keyorixhq/keyorix/internal/cli.version=$(VERSION)"

.PHONY: build build-cli build-server install install-cli install-server clean run dev

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
