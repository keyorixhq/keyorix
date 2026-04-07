#!/bin/bash

# Multi-Platform Build Script
# Builds binaries for multiple operating systems and architectures

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

echo "🌍 Multi-Platform Build for Keyorix"
echo "===================================="

# Get version info
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Git Commit: $GIT_COMMIT"
echo ""

# Define target platforms
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
    "freebsd/amd64"
)

# Create dist directory
DIST_DIR="dist"
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

# Build for each platform
for platform in "${PLATFORMS[@]}"; do
    IFS='/' read -r os arch <<< "$platform"
    
    log_info "Building for $os/$arch..."
    
    # Create platform-specific directory
    PLATFORM_DIR="$DIST_DIR/keyorix-$VERSION-$os-$arch"
    mkdir -p "$PLATFORM_DIR"
    
    # Set build environment
    export GOOS="$os"
    export GOARCH="$arch"
    
    # Determine binary extension
    EXT=""
    if [ "$os" = "windows" ]; then
        EXT=".exe"
    fi
    
    # Build flags
    BUILD_FLAGS="-ldflags='-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT'"
    
    # Build CLI
    if eval "go build $BUILD_FLAGS -o $PLATFORM_DIR/keyorix$EXT ./cmd/keyorix"; then
        log_success "CLI built for $os/$arch"
    else
        log_warning "Failed to build CLI for $os/$arch"
        continue
    fi
    
    # Build server
    if eval "go build $BUILD_FLAGS -o $PLATFORM_DIR/keyorix-server$EXT ./server"; then
        log_success "Server built for $os/$arch"
    else
        log_warning "Failed to build server for $os/$arch"
        continue
    fi
    
    # Copy configuration files
    cp keyorix-simple.yaml "$PLATFORM_DIR/" 2>/dev/null || true
    
    # Create README for the platform
    cat > "$PLATFORM_DIR/README.md" << EOF
# Keyorix $VERSION - $os/$arch

## Quick Start

### CLI Usage
\`\`\`bash
./keyorix --help
./keyorix secret create "my-secret" "secret-value"
./keyorix secret list
\`\`\`

### Server Usage
\`\`\`bash
./keyorix-server --config keyorix-simple.yaml
\`\`\`

Then visit: http://localhost:8080

## Configuration

Edit \`keyorix-simple.yaml\` to customize settings.

## Documentation

Visit: https://github.com/your-org/keyorix

## Version Information
- Version: $VERSION
- Build Time: $BUILD_TIME
- Git Commit: $GIT_COMMIT
- Platform: $os/$arch
EOF
    
    # Create archive
    cd "$DIST_DIR"
    ARCHIVE_NAME="keyorix-$VERSION-$os-$arch"
    
    if [ "$os" = "windows" ]; then
        # Create ZIP for Windows
        if command -v zip &> /dev/null; then
            zip -r "$ARCHIVE_NAME.zip" "$ARCHIVE_NAME/"
            log_success "Created $ARCHIVE_NAME.zip"
        fi
    else
        # Create tar.gz for Unix-like systems
        if command -v tar &> /dev/null; then
            tar -czf "$ARCHIVE_NAME.tar.gz" "$ARCHIVE_NAME/"
            log_success "Created $ARCHIVE_NAME.tar.gz"
        fi
    fi
    
    cd ..
done

# Create checksums
log_info "Creating checksums..."
cd "$DIST_DIR"
if command -v sha256sum &> /dev/null; then
    sha256sum *.zip *.tar.gz > checksums.txt 2>/dev/null || true
elif command -v shasum &> /dev/null; then
    shasum -a 256 *.zip *.tar.gz > checksums.txt 2>/dev/null || true
fi
cd ..

# Display results
echo ""
log_success "Multi-platform build completed!"
echo ""
echo "📦 Distribution Files:"
echo "====================="
ls -la "$DIST_DIR"/ | grep -E '\.(zip|tar\.gz)$' || true
echo ""
echo "📊 Archive Sizes:"
echo "================"
du -h "$DIST_DIR"/*.{zip,tar.gz} 2>/dev/null || true
echo ""
log_success "All platform builds ready in ./$DIST_DIR/ directory! 🎉"