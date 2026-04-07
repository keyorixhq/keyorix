#!/bin/bash

# Start Keyorix Server Script
# Starts the server with proper configuration

set -e

echo "🚀 Starting Keyorix Server"
echo "==========================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Go to project root
cd ..

# Check if server is already running
if curl -s http://localhost:8080/health > /dev/null 2>&1; then
    log_warning "Server is already running on port 8080"
    echo "Access points:"
    echo "  - Health: http://localhost:8080/health"
    echo "  - API Docs: http://localhost:8080/swagger/"
    echo "  - OpenAPI: http://localhost:8080/openapi.yaml"
    exit 0
fi

# Check if config exists
if [ ! -f "keyorix-simple.yaml" ]; then
    log_warning "Configuration file not found. Run ./scripts/deploy-simple.sh first."
    exit 1
fi

# Start server
log_info "Starting server with configuration: keyorix-simple.yaml"
log_info "Server will run on: http://localhost:8080"

cd server
KEYORIX_CONFIG_PATH=../bin/keyorix-simple.yaml ./bin/keyorix-server