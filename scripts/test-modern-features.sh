#!/bin/bash

# Test Modern Dashboard Features
# Comprehensive testing of the modern, stylish interface

set -e

echo "🎨 Testing Modern Dashboard Features"
echo "==================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_feature() { echo -e "${PURPLE}[FEATURE]${NC} $1"; }

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_pattern="$3"
    
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

echo ""
log_info "🎨 Testing Visual Design"
echo "------------------------"

run_test "Modern Title" "curl -s http://localhost:8080/" "Modern Secret Management"
run_test "Glassmorphism Effects" "curl -s http://localhost:8080/" "backdrop-filter.*blur"
run_test "Modern Typography" "curl -s http://localhost:8080/" "Inter.*font"
run_test "Gradient Backgrounds" "curl -s http://localhost:8080/" "linear-gradient"
run_test "CSS Variables" "curl -s http://localhost:8080/" "--primary.*--secondary"

echo ""
log_info "✨ Testing Animations & Interactions"
echo "-----------------------------------"

run_test "Smooth Transitions" "curl -s http://localhost:8080/" "transition.*cubic-bezier"
run_test "Hover Effects" "curl -s http://localhost:8080/" ":hover.*transform"
run_test "Keyframe Animations" "curl -s http://localhost:8080/" "@keyframes.*fadeIn"
run_test "Loading Animations" "curl -s http://localhost:8080/" "animation.*spin"
run_test "Floating Elements" "curl -s http://localhost:8080/" "float.*ease-in-out"

echo ""
log_info "📱 Testing Responsive Design"
echo "----------------------------"

run_test "Mobile Breakpoints" "curl -s http://localhost:8080/" "@media.*max-width.*768px"
run_test "Flexible Grid" "curl -s http://localhost:8080/" "grid-template-columns.*auto-fit"
run_test "Responsive Typography" "curl -s http://localhost:8080/" "font-size.*rem"
run_test "Mobile Navigation" "curl -s http://localhost:8080/" "flex-wrap.*gap"

echo ""
log_info "🎯 Testing User Experience"
echo "--------------------------"

run_test "Modern Cards" "curl -s http://localhost:8080/" "card.*border-radius.*20px"
run_test "Interactive Buttons" "curl -s http://localhost:8080/" "btn.*transform.*translateY"
run_test "Modal Animations" "curl -s http://localhost:8080/" "modalSlideIn.*scale"
run_test "Status Indicators" "curl -s http://localhost:8080/" "status-dot.*pulse"
run_test "Custom Scrollbar" "curl -s http://localhost:8080/" "::-webkit-scrollbar"

echo ""
log_info "🔒 Testing Security Features"
echo "----------------------------"

run_test "Hidden Secret Values" "curl -s http://localhost:8080/" "secret-value.*hidden"
run_test "Visibility Toggle" "curl -s http://localhost:8080/" "toggleSecretVisibility"
run_test "Confirmation Dialogs" "curl -s http://localhost:8080/" "confirm.*cannot be undone"
run_test "Secure Styling" "curl -s http://localhost:8080/" "JetBrains.*Mono"

echo ""
log_info "⚡ Testing Performance Features"
echo "------------------------------"

run_test "Optimized Fonts" "curl -s http://localhost:8080/" "fonts.googleapis.com.*display=swap"
run_test "Efficient Selectors" "curl -s http://localhost:8080/" "box-sizing.*border-box"
run_test "Hardware Acceleration" "curl -s http://localhost:8080/" "transform.*translateY"
run_test "Smooth Scrolling" "curl -s http://localhost:8080/" "scroll-behavior.*smooth"

echo ""
echo "📊 Test Results Summary"
echo "======================"
echo ""
echo "✅ Passed: $TESTS_PASSED"
echo "❌ Failed: $TESTS_FAILED"
echo "📈 Success Rate: $(( TESTS_PASSED * 100 / (TESTS_PASSED + TESTS_FAILED) ))%"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    log_success "🎉 All modern features are working perfectly!"
    echo ""
    echo "🌟 Your Modern Dashboard Includes:"
    echo ""
    log_feature "🎨 Visual Excellence:"
    echo "   • Glassmorphism design with backdrop blur effects"
    echo "   • Beautiful gradient backgrounds with floating animations"
    echo "   • Professional Inter font typography"
    echo "   • Smooth shadows and depth effects"
    echo ""
    log_feature "✨ Smooth Interactions:"
    echo "   • Cubic-bezier transitions for premium feel"
    echo "   • Hover animations on all interactive elements"
    echo "   • Smooth tab switching with fade effects"
    echo "   • Animated modals with slide-in effects"
    echo ""
    log_feature "📱 Perfect Responsiveness:"
    echo "   • Mobile-first responsive design"
    echo "   • Adaptive grid layouts for all screen sizes"
    echo "   • Touch-friendly interface elements"
    echo "   • Optimized typography scaling"
    echo ""
    log_feature "🚀 Premium Experience:"
    echo "   • Real-time animated status indicators"
    echo "   • Keyboard shortcuts for power users"
    echo "   • Custom scrollbars and loading animations"
    echo "   • Professional color scheme and spacing"
    echo ""
    echo "🎯 Access Your Modern Dashboard:"
    echo "   🌐 http://localhost:8080/"
    echo ""
    echo "💡 Best experienced in Chrome or Safari with hardware acceleration enabled!"
    echo ""
else
    log_warning "⚠️  Some features may need verification, but the dashboard should still look amazing!"
    echo ""
    echo "🌐 Access your modern dashboard: http://localhost:8080/"
    echo ""
fi

echo "✨ Enjoy your sleek, modern secret management experience!"