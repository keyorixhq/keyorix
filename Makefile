BINARY_NAME=keyorix
BUILD_DIR=./bin
VERSION?=dev
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: build install clean run dev

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

install: build
	sudo mv $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

clean:
	rm -rf $(BUILD_DIR)

run:
	KEYORIX_DB_PASSWORD=testpassword123 go run server/main.go

dev: install
	@echo "✓ keyorix installed to /usr/local/bin"
	@echo "✓ Run 'keyorix --help' to get started"
