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
    LATEST=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
elif command -v wget >/dev/null 2>&1; then
    LATEST=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/') # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
else
    error "curl or wget is required to install Keyorix."
fi

if [ -z "$LATEST" ]; then
    error "Could not determine latest version. Check https://github.com/${REPO}/releases"
fi

info "Latest version: ${LATEST}"

# Download URL — release assets are named with underscores (keyorix_linux_amd64).
BINARY_NAME="${BINARY}_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY_NAME}"

# Download binary
TMP_DIR="$(mktemp -d)"
TMP_BIN="${TMP_DIR}/${BINARY}"

info "Downloading ${BINARY_NAME}..."
if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}"
else
    wget -qO "$TMP_BIN" "$DOWNLOAD_URL" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}" # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
fi

# Verify SHA-256 checksum against the release's published checksums.txt.
info "Verifying checksum..."
CHECKSUMS_URL="https://github.com/${REPO}/releases/download/${LATEST}/checksums.txt"
if command -v curl >/dev/null 2>&1; then
    EXPECTED=$(curl --proto '=https' --tlsv1.2 -fsSL "$CHECKSUMS_URL" | awk -v n="$BINARY_NAME" '$2==n {print $1}')
else
    EXPECTED=$(wget -qO- "$CHECKSUMS_URL" | awk -v n="$BINARY_NAME" '$2==n {print $1}') # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
fi

if [ -n "$EXPECTED" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL=$(sha256sum "$TMP_BIN" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL=$(shasum -a 256 "$TMP_BIN" | awk '{print $1}')
    else
        ACTUAL=""
    fi
    if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED" ]; then
        error "Checksum mismatch for ${BINARY_NAME}: expected ${EXPECTED}, got ${ACTUAL}. Aborting."
    fi
    if [ -n "$ACTUAL" ]; then
        success "Checksum verified"
    else
        info "No sha256 tool found; skipping checksum verification"
    fi
else
    info "No checksum published for ${BINARY_NAME}; skipping verification"
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
echo "  keyorix connect http://your-server --username admin --password your-password" # NOSONAR -- documentation string, not a network connection
echo "  keyorix secret list"
echo ""
echo "  Docs: https://github.com/${REPO}"
