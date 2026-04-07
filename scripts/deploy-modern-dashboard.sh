#!/bin/bash

# Deploy Modern Stylish Dashboard
# Deploys the sleek, modern web interface for Keyorix

set -e

echo "✨ Deploying Modern Keyorix Dashboard"
echo "===================================="

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

# Check server status
log_info "Checking server status..."
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Keyorix server is running"
else
    log_error "❌ Keyorix server is not running"
    echo "Please start the server first: ./scripts/start-server.sh"
    exit 1
fi

# Deploy modern dashboard
log_info "Deploying modern dashboard..."
cp web/dist/modern-dashboard.html web/dist/index.html
log_success "✅ Modern dashboard deployed"

# Test modern dashboard features
log_info "Testing modern dashboard features..."

# Test basic loading
if curl -s http://localhost:8080/ | grep -q "Modern Secret Management"; then
    log_success "✅ Modern dashboard loads correctly"
else
    log_error "❌ Modern dashboard loading failed"
    exit 1
fi

# Test modern styling
if curl -s http://localhost:8080/ | grep -q "glassmorphism\|backdrop-filter\|Inter"; then
    log_success "✅ Modern styling applied"
else
    log_warning "⚠️  Some modern styles may not be loaded"
fi

# Test responsive design
if curl -s http://localhost:8080/ | grep -q "@media.*max-width"; then
    log_success "✅ Responsive design implemented"
else
    log_warning "⚠️  Responsive design may need verification"
fi

echo ""
echo "🎨 Modern Dashboard Features"
echo "=========================="
echo ""

log_feature "🌟 Visual Design:"
echo "   • Glassmorphism effects with backdrop blur"
echo "   • Smooth animations and transitions"
echo "   • Modern gradient backgrounds"
echo "   • Professional typography (Inter font)"
echo "   • Floating elements with depth"
echo ""

log_feature "🎯 User Experience:"
echo "   • Intuitive navigation with hover effects"
echo "   • Smooth tab transitions"
echo "   • Interactive modals with animations"
echo "   • Real-time status indicators"
echo "   • Keyboard shortcuts (Ctrl+N, Ctrl+R)"
echo ""

log_feature "📱 Responsive Design:"
echo "   • Mobile-first approach"
echo "   • Adaptive grid layouts"
echo "   • Touch-friendly interface"
echo "   • Optimized for all screen sizes"
echo ""

log_feature "🔒 Security Features:"
echo "   • Hidden secret values by default"
echo "   • Secure visibility toggles"
echo "   • Confirmation dialogs for destructive actions"
echo "   • Visual security indicators"
echo ""

log_feature "⚡ Performance:"
echo "   • Optimized animations"
echo "   • Efficient DOM updates"
echo "   • Smooth scrolling"
echo "   • Fast loading times"
echo ""

echo "🚀 Access Your Modern Dashboard"
echo "=============================="
echo ""
log_success "Your sleek, modern dashboard is ready!"
echo ""
echo "🌐 Dashboard URL: http://localhost:8080/"
echo ""
echo "✨ Modern Features to Explore:"
echo "   1. 🎨 Beautiful glassmorphism design"
echo "   2. 📊 Animated statistics cards"
echo "   3. 🔄 Smooth tab transitions"
echo "   4. 💫 Floating action buttons"
echo "   5. 🌈 Gradient backgrounds"
echo "   6. 📱 Perfect mobile experience"
echo "   7. ⌨️  Keyboard shortcuts"
echo "   8. 🎭 Hover animations"
echo ""

echo "🎯 Quick Actions:"
echo "   • Press Ctrl+N to create a new secret"
echo "   • Press Ctrl+R to refresh data"
echo "   • Press Escape to close modals"
echo "   • Hover over elements to see animations"
echo ""

# Show current system status with style
log_info "Current System Status:"
HEALTH_DATA=$(curl -s http://localhost:8080/health)
echo "   🟢 Status: $(echo $HEALTH_DATA | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo "   📦 Version: $(echo $HEALTH_DATA | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
echo "   💾 Database: $(echo $HEALTH_DATA | grep -o '"database":{"latency":"[^"]*","status":"[^"]*"}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo "   🔐 Encryption: $(echo $HEALTH_DATA | grep -o '"encryption":{"provider":"[^"]*","status":"[^"]*"}' | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo ""

log_success "🎉 Modern dashboard deployment complete!"
echo ""
echo "💡 Pro Tips:"
echo "   • Use Chrome or Safari for best visual effects"
echo "   • Enable hardware acceleration for smooth animations"
echo "   • Try the dashboard on different devices"
echo "   • Explore all the interactive elements"
echo ""
echo "Open http://localhost:8080/ and experience the modern interface!"