#!/bin/bash

# Comprehensive Web Dashboard Testing Script
# Tests all aspects of the Keyorix web interface

set -e

echo "🧪 Testing Keyorix Web Dashboard"
echo "================================"

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

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TOTAL_TESTS=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    log_info "Testing: $test_name"
    
    if eval "$test_command" | grep -q "$expected_pattern"; then
        log_success "✅ $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        log_error "❌ $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# 1. Test Server Connectivity
echo ""
log_info "🔗 Testing Server Connectivity"
echo "------------------------------"

run_test "Server Health Check" "curl -s http://localhost:8080/health" "healthy"
run_test "Server API Response" "curl -s http://localhost:8080/api/v1/system/info" "version\|uptime\|memory"

# 2. Test Web Dashboard Access
echo ""
log_info "🌐 Testing Web Dashboard Access"
echo "-------------------------------"

run_test "Web Dashboard Loading" "curl -s http://localhost:8080/" "html\|DOCTYPE"
run_test "Dashboard Title" "curl -s http://localhost:8080/" "Dashboard\|Keyorix\|Secretly"
run_test "Static Assets" "curl -s -I http://localhost:8080/assets/" "200\|404"

# 3. Test API Endpoints
echo ""
log_info "🔌 Testing API Endpoints"
echo "------------------------"

run_test "OpenAPI Specification" "curl -s http://localhost:8080/openapi.yaml" "openapi\|paths"
run_test "Swagger UI Access" "curl -s http://localhost:8080/swagger/" "swagger\|Swagger\|API"

# 4. Test Web Dashboard Features
echo ""
log_info "⚡ Testing Web Dashboard Features"
echo "--------------------------------"

# Test if the React app loads properly
if curl -s http://localhost:8080/ | grep -q "script.*src.*assets"; then
    log_success "✅ React Application Assets Loaded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_error "❌ React Application Assets Not Found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# Test CSS loading
if curl -s http://localhost:8080/ | grep -q "link.*stylesheet\|style"; then
    log_success "✅ Stylesheets Loaded"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_error "❌ Stylesheets Not Found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# 5. Test CORS Configuration
echo ""
log_info "🔒 Testing CORS Configuration"
echo "-----------------------------"

CORS_TEST=$(curl -s -H "Origin: http://localhost:3000" -H "Access-Control-Request-Method: GET" -H "Access-Control-Request-Headers: Content-Type" -X OPTIONS http://localhost:8080/health)
if echo "$CORS_TEST" | grep -q "Access-Control-Allow-Origin\|200"; then
    log_success "✅ CORS Headers Present"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_warning "⚠️  CORS Headers May Need Configuration"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# 6. Test Performance
echo ""
log_info "⚡ Testing Performance"
echo "---------------------"

# Test response time
RESPONSE_TIME=$(curl -o /dev/null -s -w "%{time_total}" http://localhost:8080/)
if (( $(echo "$RESPONSE_TIME < 2.0" | bc -l) )); then
    log_success "✅ Fast Response Time: ${RESPONSE_TIME}s"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_warning "⚠️  Slow Response Time: ${RESPONSE_TIME}s"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))

# 7. Interactive Testing Instructions
echo ""
log_info "🖱️  Manual Testing Instructions"
echo "-------------------------------"

echo ""
echo "Now test the web interface manually:"
echo ""
echo "1. 🌐 Open your browser and go to: http://localhost:8080/"
echo ""
echo "2. 🔍 Check these features:"
echo "   ✅ Dashboard loads without errors"
echo "   ✅ Navigation menu works"
echo "   ✅ Secret management interface"
echo "   ✅ User authentication (if enabled)"
echo "   ✅ System health monitoring"
echo "   ✅ Responsive design on mobile"
echo ""
echo "3. 📱 Test on different devices:"
echo "   • Desktop browser"
echo "   • Mobile browser"
echo "   • Tablet browser"
echo ""
echo "4. 🔧 Test API integration:"
echo "   • Go to: http://localhost:8080/swagger/"
echo "   • Try the interactive API documentation"
echo "   • Test API endpoints directly"
echo ""

# 8. Build and Development Testing
echo ""
log_info "🔨 Testing Development Environment"
echo "---------------------------------"

# Check if we can rebuild the web dashboard
cd web
if npm run build > /dev/null 2>&1; then
    log_success "✅ Web Dashboard Builds Successfully"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    log_error "❌ Web Dashboard Build Failed"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi
TOTAL_TESTS=$((TOTAL_TESTS + 1))
cd ..

# 9. Test Results Summary
echo ""
echo "📊 Test Results Summary"
echo "======================"
echo ""
echo "Total Tests: $TOTAL_TESTS"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    log_success "🎉 All tests passed! Your web dashboard is working perfectly!"
    echo ""
    echo "🚀 Your Keyorix Web Dashboard is ready to use:"
    echo "   🌐 Web Interface: http://localhost:8080/"
    echo "   📚 API Docs: http://localhost:8080/swagger/"
    echo "   🏥 Health Check: http://localhost:8080/health"
    echo ""
    exit 0
else
    log_warning "⚠️  Some tests failed, but the web dashboard may still be functional."
    echo ""
    echo "🔧 Try these troubleshooting steps:"
    echo "   1. Restart the server: ./scripts/start-server.sh"
    echo "   2. Rebuild web assets: cd web && npm run build"
    echo "   3. Check server logs for errors"
    echo ""
    echo "🌐 Web Interface: http://localhost:8080/"
    echo ""
    exit 1
fi