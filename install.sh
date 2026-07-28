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

info()    { local msg="$1"; printf "${BLUE}→${NC} %s\n" "$msg"; }
success() { local msg="$1"; printf "${GREEN}✓${NC} %s\n" "$msg"; }
error()   { local msg="$1"; printf "${RED}✗${NC} %s\n" "$msg" >&2; exit 1; }

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
    LATEST=$(curl --proto '=https' --tlsv1.2 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/') # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; redirect-following is required for GitHub API
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
    curl --proto '=https' --tlsv1.2 -fsSL "$DOWNLOAD_URL" -o "$TMP_BIN" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}" # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; redirect-following is required for GitHub release CDN
else
    wget -qO "$TMP_BIN" "$DOWNLOAD_URL" || error "Download failed. Check https://github.com/${REPO}/releases/${LATEST}" # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
fi

# SC-014: Verify checksums.txt supply-chain integrity with cosign before trusting
# its contents.  checksums.txt is keylessly signed in CI (see SECURITY.md); a
# tampered checksums.txt would otherwise let an attacker substitute any binary
# while still passing the SHA-256 check below.
info "Downloading checksums.txt..."
CHECKSUMS_BASE="https://github.com/${REPO}/releases/download/${LATEST}"
TMP_CHECKSUMS="${TMP_DIR}/checksums.txt"
TMP_CHECKSUMS_PEM="${TMP_DIR}/checksums.txt.pem"
TMP_CHECKSUMS_SIG="${TMP_DIR}/checksums.txt.sig"
if command -v curl >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -fsSL "${CHECKSUMS_BASE}/checksums.txt" -o "$TMP_CHECKSUMS" || error "Failed to download checksums.txt" # NOSONAR -- bash:S6506 false positive: --proto '=https' --tlsv1.2 enforces HTTPS; redirect-following is required for GitHub release CDN
else
    wget -qO "$TMP_CHECKSUMS" "${CHECKSUMS_BASE}/checksums.txt" || error "Failed to download checksums.txt" # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
fi

# Verify checksums.txt with cosign (fail hard if cosign is present but verification fails).
# SC-014 / SC-R124-001: when cosign is installed, .pem/.sig artifact downloads are
# mandatory and hard-fail on any error — a download failure must NOT be silently
# treated as "not published" since an attacker can force failures while serving a
# tampered checksums.txt, downgrading verification without cosign exiting non-zero.
COSIGN_IDENTITY_REGEXP="https://github.com/${REPO}/\\.github/workflows/release\\.yml@.*"
if command -v cosign >/dev/null 2>&1; then
    if command -v curl >/dev/null 2>&1; then
        curl --proto '=https' --tlsv1.2 -fsSL "${CHECKSUMS_BASE}/checksums.txt.pem" -o "$TMP_CHECKSUMS_PEM" \
            || error "cosign: checksums.txt.pem download failed — aborting (supply-chain integrity check; see SECURITY.md)" # NOSONAR -- bash:S6506 false positive
        curl --proto '=https' --tlsv1.2 -fsSL "${CHECKSUMS_BASE}/checksums.txt.sig" -o "$TMP_CHECKSUMS_SIG" \
            || error "cosign: checksums.txt.sig download failed — aborting (supply-chain integrity check; see SECURITY.md)" # NOSONAR -- bash:S6506 false positive
    else
        wget -qO "$TMP_CHECKSUMS_PEM" "${CHECKSUMS_BASE}/checksums.txt.pem" \
            || error "cosign: checksums.txt.pem download failed — aborting (supply-chain integrity check; see SECURITY.md)" # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
        wget -qO "$TMP_CHECKSUMS_SIG" "${CHECKSUMS_BASE}/checksums.txt.sig" \
            || error "cosign: checksums.txt.sig download failed — aborting (supply-chain integrity check; see SECURITY.md)" # NOSONAR -- wget lacks --https-only on BusyBox; URL is already https://
    fi
    cosign verify-blob \
        --certificate "$TMP_CHECKSUMS_PEM" \
        --signature   "$TMP_CHECKSUMS_SIG" \
        --certificate-identity-regexp "$COSIGN_IDENTITY_REGEXP" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "$TMP_CHECKSUMS" || error "cosign: checksums.txt signature verification FAILED — aborting (supply-chain integrity check)"
    success "checksums.txt cosign signature verified"
else
    printf "${RED}WARNING:${NC} cosign is not installed — checksums.txt signature not verified.\n" >&2
    printf "  To verify supply-chain integrity, install cosign (https://docs.sigstore.dev/)\n" >&2
    printf "  and re-run, or verify manually per SECURITY.md.\n" >&2
fi

# Verify SHA-256 checksum of the downloaded binary against the (now-verified) checksums.txt.
info "Verifying checksum..."
EXPECTED=$(awk -v n="$BINARY_NAME" '$2==n {print $1}' "$TMP_CHECKSUMS")

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
