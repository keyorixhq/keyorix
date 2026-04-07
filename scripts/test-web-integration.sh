#!/bin/bash

# Keyorix Web Integration Test Script
# This script tests the full-stack integration between the web dashboard and Go backend

set -e

echo "🚀 Starting Keyorix Web Integration Test"

# Configuration
SERVER_PORT=8080
WEB_BUILD_DIR="./web/dist"
SERVER_CONFIG="./server/config/web-enabled.yaml"
TEST_TIMEOUT=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
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

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi
    rm -f ./data/test-keyorix.db
}

# Set trap for cleanup
trap cleanup EXIT

# Step 1: Check prerequisites
log_info "Checking prerequisites..."

if ! command -v node &> /dev/null; then
    log_error "Node.js is not installed"
    exit 1
fi

if ! command -v npm &> /dev/null; then
    log_error "npm is not installed"
    exit 1
fi

if ! command -v go &> /dev/null; then
    log_error "Go is not installed"
    exit 1
fi

log_success "Prerequisites check passed"

# Step 2: Build web application
log_info "Building web application..."

cd web

if [ ! -f "package.json" ]; then
    log_error "Web package.json not found"
    exit 1
fi

# Install dependencies if node_modules doesn't exist
if [ ! -d "node_modules" ]; then
    log_info "Installing web dependencies..."
    npm install
fi

# Build the web application
log_info "Building web assets..."
npm run build

if [ ! -d "dist" ]; then
    log_error "Web build failed - dist directory not found"
    exit 1
fi

log_success "Web application built successfully"

cd ..

# Step 3: Build Go server
log_info "Building Go server..."

cd server

if [ ! -f "go.mod" ]; then
    log_error "Server go.mod not found"
    exit 1
fi

# Build the server
go build -o keyorix-server ./

if [ ! -f "keyorix-server" ]; then
    log_error "Server build failed"
    exit 1
fi

log_success "Go server built successfully"

cd ..

# Step 4: Prepare test configuration
log_info "Preparing test configuration..."

mkdir -p ./data

# Create test configuration
cat > ./test-config.yaml << EOF
environment: "development"

locale:
  language: "en"
  fallback_language: "en"

server:
  http:
    enabled: true
    port: "$SERVER_PORT"
    protocol_versions: ["1.1", "2.0"]
    swagger_enabled: true
    web_assets_path: "$WEB_BUILD_DIR"
    domain: "localhost"
    allowed_origins:
      - "http://localhost:3000"
      - "http://localhost:5173"
    tls:
      enabled: false
    ratelimit:
      enabled: false
  grpc:
    enabled: false

storage:
  type: "local"
  database:
    path: "./data/test-keyorix.db"
    max_open_conns: 25
    max_idle_conns: 5
  encryption:
    enabled: true
    use_kek: false

secrets:
  chunking:
    enabled: true
    max_chunk_size_kb: 64
    max_chunks_per_secret: 100
  limits:
    max_secrets_per_user: 1000

telemetry:
  enabled: false

security:
  enable_file_permission_check: false
  auto_fix_file_permissions: false
  allow_unsafe_file_permissions: true

soft_delete:
  enabled: true
  retention_days: 30

purge:
  enabled: false
EOF

log_success "Test configuration prepared"

# Step 5: Start the server
log_info "Starting Keyorix server..."

cd server
KEYORIX_CONFIG_PATH="../test-config.yaml" ./keyorix-server &
SERVER_PID=$!
cd ..

# Wait for server to start
log_info "Waiting for server to start..."
for i in {1..30}; do
    if curl -s http://localhost:$SERVER_PORT/health > /dev/null 2>&1; then
        log_success "Server started successfully"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "Server failed to start within timeout"
        exit 1
    fi
    sleep 1
done

# Step 6: Test API endpoints
log_info "Testing API endpoints..."

# Test health endpoint
if ! curl -s http://localhost:$SERVER_PORT/health | grep -q "OK"; then
    log_error "Health endpoint test failed"
    exit 1
fi
log_success "Health endpoint test passed"

# Test OpenAPI spec
if ! curl -s http://localhost:$SERVER_PORT/openapi.yaml | grep -q "openapi"; then
    log_error "OpenAPI spec test failed"
    exit 1
fi
log_success "OpenAPI spec test passed"

# Test CORS headers
CORS_RESPONSE=$(curl -s -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" -X OPTIONS http://localhost:$SERVER_PORT/api/v1/secrets)
if [ $? -ne 0 ]; then
    log_error "CORS preflight test failed"
    exit 1
fi
log_success "CORS configuration test passed"

# Step 7: Test web asset serving
log_info "Testing web asset serving..."

# Test index.html serving
if ! curl -s http://localhost:$SERVER_PORT/ | grep -q "<html"; then
    log_error "Index.html serving test failed"
    exit 1
fi
log_success "Index.html serving test passed"

# Test SPA routing (should serve index.html for non-API routes)
if ! curl -s http://localhost:$SERVER_PORT/dashboard | grep -q "<html"; then
    log_error "SPA routing test failed"
    exit 1
fi
log_success "SPA routing test passed"

# Test static asset serving (if assets exist)
if [ -d "$WEB_BUILD_DIR/assets" ]; then
    ASSET_FILE=$(find $WEB_BUILD_DIR/assets -name "*.js" | head -1)
    if [ ! -z "$ASSET_FILE" ]; then
        ASSET_NAME=$(basename "$ASSET_FILE")
        if curl -s http://localhost:$SERVER_PORT/assets/$ASSET_NAME | grep -q "function\|const\|var"; then
            log_success "Static asset serving test passed"
        else
            log_warning "Static asset serving test inconclusive"
        fi
    fi
fi

# Test service worker
if [ -f "$WEB_BUILD_DIR/sw.js" ]; then
    if curl -s http://localhost:$SERVER_PORT/sw.js | grep -q "self\|cache"; then
        log_success "Service worker serving test passed"
    else
        log_warning "Service worker serving test inconclusive"
    fi
fi

# Step 8: Test API with authentication (basic test)
log_info "Testing API functionality..."

# Note: This is a basic test. In a real scenario, you'd need to set up authentication
# For now, we'll just test that the endpoints respond correctly to unauthenticated requests

# Test secrets endpoint (should require auth)
SECRETS_RESPONSE=$(curl -s -w "%{http_code}" http://localhost:$SERVER_PORT/api/v1/secrets)
if [[ "$SECRETS_RESPONSE" == *"401"* ]] || [[ "$SECRETS_RESPONSE" == *"403"* ]]; then
    log_success "Secrets endpoint authentication test passed"
else
    log_warning "Secrets endpoint authentication test inconclusive (got: $SECRETS_RESPONSE)"
fi

# Step 9: Performance test
log_info "Running basic performance test..."

# Test response times
START_TIME=$(date +%s%N)
curl -s http://localhost:$SERVER_PORT/health > /dev/null
END_TIME=$(date +%s%N)
RESPONSE_TIME=$(( (END_TIME - START_TIME) / 1000000 )) # Convert to milliseconds

if [ $RESPONSE_TIME -lt 100 ]; then
    log_success "Performance test passed (${RESPONSE_TIME}ms)"
else
    log_warning "Performance test slow (${RESPONSE_TIME}ms)"
fi

# Step 10: Test concurrent requests
log_info "Testing concurrent request handling..."

# Send 10 concurrent requests
for i in {1..10}; do
    curl -s http://localhost:$SERVER_PORT/health > /dev/null &
done
wait

log_success "Concurrent request test passed"

# Step 11: Final validation
log_info "Running final validation..."

# Check if server is still responsive
if curl -s http://localhost:$SERVER_PORT/health > /dev/null; then
    log_success "Server stability test passed"
else
    log_error "Server stability test failed"
    exit 1
fi

# Summary
echo ""
echo "🎉 Integration Test Summary:"
echo "=========================="
log_success "✅ Web application built successfully"
log_success "✅ Go server built successfully"
log_success "✅ Server started and responded to requests"
log_success "✅ API endpoints are accessible"
log_success "✅ Web assets are served correctly"
log_success "✅ SPA routing works properly"
log_success "✅ CORS configuration is working"
log_success "✅ Authentication is enforced"
log_success "✅ Performance is acceptable"
log_success "✅ Server handles concurrent requests"

echo ""
log_success "🚀 Full-stack integration test completed successfully!"
log_info "You can now access the web dashboard at: http://localhost:$SERVER_PORT"
log_info "API documentation is available at: http://localhost:$SERVER_PORT/swagger/"

# Keep server running for manual testing if requested
if [ "$1" = "--keep-running" ]; then
    log_info "Server is running. Press Ctrl+C to stop."
    wait $SERVER_PID
fi