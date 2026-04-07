#!/bin/bash

# Simple Deployment Script
# Deploys just the core CLI and server system

set -e

echo "🚀 Simple Keyorix Deployment"
echo "============================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }

# Step 1: Build everything
log_info "Building CLI and server..."

# Go to project root
cd ..

# Build CLI
go build -o keyorix ./
log_success "CLI built: ./bin/keyorix"

# Build server
cd server
go build -o keyorix-server ./
cd ..
log_success "Server built: ./serve./bin/keyorix-server"

# Step 2: Create basic config
log_info "Creating basic configuration..."

cat > keyorix-simple.yaml << 'EOF'
environment: "development"

locale:
  language: "en"
  fallback_language: "en"

server:
  http:
    enabled: true
    port: "8080"
    protocol_versions: ["1.1", "2.0"]
    swagger_enabled: true
    tls:
      enabled: false
    ratelimit:
      enabled: false
  grpc:
    enabled: false

storage:
  type: "local"
  database:
    path: "./dat./bin/keyorix.db"
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

log_success "Configuration created: keyorix-simple.yaml"

# Step 3: Create data directory
mkdir -p data
log_success "Data directory created"

# Step 4: Test CLI
log_info "Testing CLI..."
./bin/keyorix --help > /dev/null
log_success "CLI is working"

echo ""
log_success "🎉 Deployment complete!"
echo ""
echo "To start the system:"
echo "  1. Start server: cd server && KEYORIX_CONFIG_PATH=../bin/keyorix-simple.yaml ./bin/keyorix-server"
echo "  2. In another terminal, test CLI: ./bin/keyorix secret list"
echo "  3. Access API: http://localhost:8080/health"
echo "  4. View API docs: http://localhost:8080/swagger/"
echo ""
log_warning "This is a development setup. For production, use the full deployment guide."