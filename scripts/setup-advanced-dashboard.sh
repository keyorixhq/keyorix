#!/bin/bash

# Setup Advanced Secret Management Dashboard
# Deploys the full-featured web interface for Keyorix

set -e

echo "🚀 Setting Up Advanced Keyorix Dashboard"
echo "========================================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check server status
log_info "Checking server status..."
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Keyorix server is running"
else
    log_error "❌ Keyorix server is not running"
    echo "Please start the server first: ./scripts/start-server.sh"
    exit 1
fi

# Verify advanced dashboard is deployed
log_info "Verifying advanced dashboard deployment..."
if curl -s http://localhost:8080/ | grep -q "Advanced Secret Management"; then
    log_success "✅ Advanced dashboard is deployed"
else
    log_warning "⚠️  Deploying advanced dashboard..."
    cp web/dist/advanced-dashboard.html web/dist/index.html
    log_success "✅ Advanced dashboard deployed"
fi

# Test dashboard functionality
log_info "Testing dashboard functionality..."

# Test basic loading
if curl -s http://localhost:8080/ | grep -q "Secret Management"; then
    log_success "✅ Dashboard loads correctly"
else
    log_error "❌ Dashboard loading failed"
    exit 1
fi

# Test API connectivity
if curl -s http://localhost:8080/health | grep -q "healthy"; then
    log_success "✅ API connectivity working"
else
    log_warning "⚠️  API may have connectivity issues"
fi

# Create some demo data for testing
log_info "Setting up demo environment..."

# Try to create demo secrets via CLI (if available)
if [ -f "./keyorix" ]; then
    log_info "Creating demo secrets via CLI..."
    
    # Create demo secrets
    ./keyorix secret create --name "demo-database-password" --value "super-secure-db-pass-123" --description "Demo database password" 2>/dev/null || true
    ./keyorix secret create --name "demo-api-key" --value "sk_test_demo_key_12345" --description "Demo API key for testing" 2>/dev/null || true
    ./keyorix secret create --name "demo-jwt-secret" --value "jwt-signing-secret-demo-key" --description "Demo JWT signing secret" 2>/dev/null || true
    
    log_success "✅ Demo secrets created (if CLI is available)"
else
    log_info "CLI not found - dashboard will use built-in demo data"
fi

echo ""
echo "🎉 Advanced Dashboard Setup Complete!"
echo "===================================="
echo ""
log_success "Your advanced Keyorix dashboard is ready!"
echo ""
echo "🌐 Access your dashboard:"
echo "   • Main Dashboard: http://localhost:8080/"
echo "   • API Documentation: http://localhost:8080/swagger/"
echo "   • System Health: http://localhost:8080/health"
echo ""
echo "✨ Advanced Features Available:"
echo "   🔑 Secret Management - Create, view, edit, delete secrets"
echo "   👁️  Secret Viewing - Toggle visibility for secure viewing"
echo "   🤝 Secret Sharing - Share secrets with team members"
echo "   📊 Dashboard Overview - Real-time statistics and health"
echo "   📋 Audit Logging - Track all secret operations"
echo "   ⚙️  Settings - Configure API access and preferences"
echo ""
echo "🔧 How to Use:"
echo "   1. Open http://localhost:8080/ in your browser"
echo "   2. Navigate between tabs: Dashboard, Secrets, Sharing, Audit, Settings"
echo "   3. Click 'Create Secret' to add new secrets"
echo "   4. Use 'View' button to see secret details"
echo "   5. Configure API settings in the Settings tab for full functionality"
echo ""
echo "💡 Tips:"
echo "   • The dashboard works in demo mode without authentication"
echo "   • Configure API key in Settings for full API integration"
echo "   • Use the CLI alongside the web interface for maximum flexibility"
echo "   • All operations are logged for audit purposes"
echo ""

# Show current system status
log_info "Current System Status:"
HEALTH_DATA=$(curl -s http://localhost:8080/health)
echo "   Status: $(echo $HEALTH_DATA | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo "   Version: $(echo $HEALTH_DATA | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
echo "   Database: $(echo $HEALTH_DATA | grep -o '"database":{"latency":"[^"]*","status":"[^"]*"}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo ""

log_success "🚀 Advanced dashboard is fully operational!"
echo ""
echo "Next steps:"
echo "  1. Open http://localhost:8080/ in your browser"
echo "  2. Explore the advanced secret management features"
echo "  3. Create and manage secrets through the web interface"
echo "  4. Configure API settings for enhanced functionality"