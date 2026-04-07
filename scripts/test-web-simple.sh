#!/bin/bash

# Simple Web Dashboard Test
# Quick verification that the web interface is working

set -e

echo "🌐 Quick Web Dashboard Test"
echo "=========================="

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

echo ""
log_info "Testing basic connectivity..."

# Test 1: Server is running
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Server is running"
else
    log_error "❌ Server is not running"
    echo "Please start the server: ./scripts/start-server.sh"
    exit 1
fi

# Test 2: Web dashboard loads
if curl -s http://localhost:8080/ | grep -q "html\|HTML"; then
    log_success "✅ Web dashboard loads"
else
    log_error "❌ Web dashboard not loading"
    exit 1
fi

# Test 3: Check if it's the React app
if curl -s http://localhost:8080/ | grep -q "script.*assets"; then
    log_success "✅ React application detected"
    APP_TYPE="React App"
else
    log_success "✅ Web interface available"
    APP_TYPE="Static Web"
fi

# Test 4: API documentation
if curl -s http://localhost:8080/swagger/ | grep -q "swagger\|Swagger\|API"; then
    log_success "✅ API documentation available"
else
    log_warning "⚠️  API documentation may need configuration"
fi

# Test 5: OpenAPI spec
if curl -s http://localhost:8080/openapi.yaml | grep -q "openapi\|paths"; then
    log_success "✅ OpenAPI specification available"
else
    log_warning "⚠️  OpenAPI specification not found"
fi

echo ""
echo "🎉 Web Dashboard Test Results"
echo "============================"
echo ""
log_success "Your Keyorix web dashboard is working!"
echo ""
echo "📱 Access your dashboard:"
echo "   🌐 Web Interface: http://localhost:8080/"
echo "   📚 API Documentation: http://localhost:8080/swagger/"
echo "   🏥 System Health: http://localhost:8080/health"
echo ""
echo "🔧 Dashboard Type: $APP_TYPE"
echo ""
echo "🖱️  Manual Testing:"
echo "   1. Open http://localhost:8080/ in your browser"
echo "   2. Verify the interface loads correctly"
echo "   3. Test navigation and features"
echo "   4. Check responsive design on mobile"
echo ""
echo "✨ Features to test:"
echo "   • Dashboard overview"
echo "   • Secret management (if auth is configured)"
echo "   • System monitoring"
echo "   • API documentation"
echo "   • Mobile responsiveness"
echo ""

# Show current system status
echo "📊 Current System Status:"
HEALTH_DATA=$(curl -s http://localhost:8080/health)
echo "   Status: $(echo $HEALTH_DATA | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo "   Version: $(echo $HEALTH_DATA | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
echo "   Uptime: $(echo $HEALTH_DATA | grep -o '"uptime":"[^"]*"' | cut -d'"' -f4)"
echo ""

log_success "🚀 Web dashboard is ready for use!"
echo ""
echo "Next steps:"
echo "  1. Open http://localhost:8080/ in your browser"
echo "  2. Explore the web interface"
echo "  3. Test secret management features"
echo "  4. Check API documentation at /swagger/"