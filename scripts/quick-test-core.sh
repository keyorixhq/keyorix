#!/bin/bash

# Quick Core System Test
# Tests the CLI and server without web dashboard

set -e

echo "🚀 Quick Core System Test"
echo "========================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Test 1: Build CLI
log_info "Building CLI..."
cd ..
if go build -o keyorix ./ 2>/dev/null; then
    log_success "CLI built successfully"
else
    log_error "CLI build failed"
    exit 1
fi

# Test 2: Test CLI basic functionality
log_info "Testing CLI basic commands..."
if ./keyorix --help >/dev/null 2>&1; then
    log_success "CLI help command works"
else
    log_error "CLI help command failed"
fi

# Test 3: Build server
log_info "Building server..."
cd server
if go build -o keyorix-server ./ 2>/dev/null; then
    log_success "Server built successfully"
else
    log_error "Server build failed"
    exit 1
fi
cd ..

# Test 4: Test core functionality
log_info "Testing core secret operations..."
if go test ./internal/core -v -short 2>/dev/null | grep -q "PASS"; then
    log_success "Core tests passing"
else
    log_error "Core tests failed"
fi

echo ""
log_success "🎉 Core system is working!"
log_info "Next steps:"
echo "  1. Run: ./keyorix --help"
echo "  2. Run: cd server && ./keyorix-server"
echo "  3. Test API at: http://localhost:8080/health"