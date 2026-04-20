#!/bin/bash
# Keyorix release build script
# Produces CLI and server binaries for macOS and Linux (amd64 + arm64)
# Usage: VERSION=v0.1.0 ./scripts/build-release.sh

set -e

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
BUILD_TIME="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"
LDFLAGS="-s -w -X github.com/keyorixhq/keyorix/internal/cli.version=${VERSION}"

DIST_DIR="dist/${VERSION}"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

echo "🔨 Building Keyorix ${VERSION}"
echo "   Commit:     ${GIT_COMMIT}"
echo "   Build time: ${BUILD_TIME}"
echo ""

PLATFORMS=("darwin/amd64" "darwin/arm64" "linux/amd64" "linux/arm64")

for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    echo "→ ${os}/${arch}"

    GOOS="$os" GOARCH="$arch" go build \
        -ldflags="${LDFLAGS}" \
        -o "${DIST_DIR}/keyorix_${os}_${arch}" \
        .

    GOOS="$os" GOARCH="$arch" go build \
        -ldflags="${LDFLAGS}" \
        -o "${DIST_DIR}/keyorix-server_${os}_${arch}" \
        ./server/main.go
done

# Checksums
echo ""
echo "→ Generating checksums"
cd "$DIST_DIR"
shasum -a 256 keyorix_* keyorix-server_* > checksums.txt
cd -

echo ""
echo "✅ Release artifacts in ${DIST_DIR}/"
ls -lh "${DIST_DIR}/"
