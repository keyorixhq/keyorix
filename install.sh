#!/bin/sh
# Keyorix CLI installer
# Usage: curl -L https://raw.githubusercontent.com/keyorixhq/keyorix/main/install.sh | sh

set -e

REPO="keyorixhq/keyorix"
BINARY="keyorix"
INSTALL_DIR="/usr/local/bin"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { printf "${BLUE}→${NC} %s\n" "$1"; }
success() { printf "${GREEN}✓${NC} %s\n" "$1"; }
error()   { printf "${RED}✗${NC} %s\n" "$1" >&2; exit 1; }

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$OS" in
    darwin) OS="darwin" ;;
    linux)  OS="linux" ;;
    *)      error "Unsupported OS: $OS. Only macOS and Linux are supported." ;;
esac

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    arm64)   ARCH="arm64" ;;
    *)       error "Unsupported architecture: $ARCH." ;;
esac

info "Detected platform: ${OS}/${ARCH}"

# Get latest version from GitHub
info "Fetching latest release..."
if command -v curl >/dev/null 2>&1; then
    LATEST=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
else
    error "curl or wget is required to install Keyorix."
fi

if [ -z "$LATEST" ]; then
    error "Could not determine latest version. Check https://github.com/${REPO}/releases"
fi

info "Latest version: ${LATEST}"

# Download URL
BINARY_NAME="${BINARY}_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY_NAME}"

# Download binary
TMP_DIR="$(mktemp -d)"
TMP_BIN="${TMP_DIR}/${BINARY}"

info "Downloading ${BINARY_NAME}..."
if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}"
else
    wget -qO "$TMP_BIN" "$DOWNLOAD_URL" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}"
fi

# Make executable
chmod +x "$TMP_BIN"

# Verify it runs
if ! "$TMP_BIN" --version >/dev/null 2>&1; then
    error "Downloaded binary failed to run. Please report this at https://github.com/${REPO}/issues"
fi

# Install
if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_BIN" "${INSTALL_DIR}/${BINARY}"
else
    info "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo mv "$TMP_BIN" "${INSTALL_DIR}/${BINARY}"
fi

rm -rf "$TMP_DIR"

success "Keyorix ${LATEST} installed to ${INSTALL_DIR}/${BINARY}"
echo ""
echo "  Get started:"
echo "  keyorix connect http://your-server --username admin --password your-password"
echo "  keyorix secret list"
echo ""
echo "  Docs: https://github.com/${REPO}"
