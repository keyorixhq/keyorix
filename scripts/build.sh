#!/bin/bash

# Comprehensive Build Script - Outputs to ./bin directory
# Supports multiple build modes and platforms

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Build configuration
BUILD_MODE="${BUILD_MODE:-release}"
TARGET_OS="${TARGET_OS:-$(go env GOOS)}"
TARGET_ARCH="${TARGET_ARCH:-$(go env GOARCH)}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo 'dev')}"
BUILD_TIME="$(date -u '+%Y-%m-%d_%H:%M:%S')"
GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')"

echo "🔨 Building Keyorix Binaries"
echo "============================="
echo "Build Mode: $BUILD_MODE"
echo "Target OS: $TARGET_OS"
echo "Target Arch: $TARGET_ARCH"
echo "Version: $VERSION"
echo "Build Time: $BUILD_TIME"
echo "Git Commit: $GIT_COMMIT"
echo ""

# Create bin directory
log_info "Creating bin directory..."
mkdir -p bin

# Build flags based on mode
if [ "$BUILD_MODE" = "debug" ]; then
    BUILD_FLAGS="-gcflags='all=-N -l'"
    log_info "Debug mode: Including debug symbols"
elif [ "$BUILD_MODE" = "release" ]; then
    BUILD_FLAGS="-ldflags='-s -w -X main.Version=$VERSION -X main.BuildTime=$BUILD_TIME -X main.GitCommit=$GIT_COMMIT'"
    log_info "Release mode: Optimized build with version info"
else
    BUILD_FLAGS=""
    log_info "Standard build mode"
fi

# Set cross-compilation environment
export GOOS="$TARGET_OS"
export GOARCH="$TARGET_ARCH"

# Build main CLI
log_info "Building CLI binary (keyorix)..."
if eval "go build $BUILD_FLAGS -o bin/keyorix ./cmd/keyorix"; then
    log_success "CLI binary built successfully"
else
    log_error "Failed to build CLI binary"
    exit 1
fi

# Build server
log_info "Building server binary (keyorix-server)..."
if eval "go build $BUILD_FLAGS -o bin/keyorix-server ./server"; then
    log_success "Server binary built successfully"
else
    log_error "Failed to build server binary"
    exit 1
fi

# Build additional tools if they exist
if [ -d "examples/secret_crud" ]; then
    log_info "Building secret_crud example..."
    if eval "go build $BUILD_FLAGS -o bin/secret_crud ./examples/secret_crud"; then
        log_success "secret_crud built successfully"
    else
        log_warning "Failed to build secret_crud"
    fi
fi

if [ -d "examples/new-architecture" ]; then
    log_info "Building new-architecture example..."
    if eval "go build $BUILD_FLAGS -o bin/new-architecture ./examples/new-architecture"; then
        log_success "new-architecture built successfully"
    else
        log_warning "Failed to build new-architecture"
    fi
fi

# Build validation tools if they exist
if [ -f "cmd/validate-translations/main.go" ]; then
    log_info "Building translation validator..."
    if eval "go build $BUILD_FLAGS -o bin/validate-translations ./cmd/validate-translations"; then
        log_success "validate-translations built successfully"
    else
        log_warning "Failed to build validate-translations"
    fi
fi

# Make binaries executable
log_info "Setting executable permissions..."
chmod +x bin/*

# Build web assets if web directory exists
if [ -d "web" ] && [ -f "web/package.json" ]; then
    log_info "Building web assets..."
    cd web
    if command -v npm &> /dev/null; then
        if [ ! -d "node_modules" ]; then
            log_info "Installing web dependencies..."
            npm install
        fi
        log_info "Building web production bundle..."
        if npm run build; then
            log_success "Web assets built successfully"
        else
            log_warning "Failed to build web assets"
        fi
    else
        log_warning "npm not found, skipping web build"
    fi
    cd ..
fi

# Create build info file
log_info "Creating build information file..."
cat > bin/build-info.txt << EOF
Keyorix Build Information
==========================
Version: $VERSION
Build Mode: $BUILD_MODE
Build Time: $BUILD_TIME
Git Commit: $GIT_COMMIT
Target OS: $TARGET_OS
Target Arch: $TARGET_ARCH
Go Version: $(go version)
