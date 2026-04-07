#!/bin/bash

# Deploy Vercel-Style Dashboard for Keyorix
# Creates a professional, trustworthy interface inspired by Vercel's design

set -e

echo "🚀 Deploying Vercel-Style Keyorix Dashboard"
echo "==========================================="

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

# Deploy Vercel-style dashboard
log_info "Deploying Vercel-style interface..."
if [ -f "web/dist/vercel-style-dashboard.html" ]; then
    cp web/dist/vercel-style-dashboard.html web/dist/index.html
    log_success "✅ Vercel-style dashboard deployed"
else
    log_error "❌ Vercel-style dashboard file not found"
    exit 1
fi

# Test the deployment
log_info "Testing Vercel-style dashboard..."
if curl -s http://localhost:8080/ | grep -q "Secret Management Platform"; then
    log_success "✅ Vercel-style dashboard is working"
else
    log_error "❌ Dashboard deployment failed"
    exit 1
fi

echo ""
echo "🎨 Vercel-Style Design Features"
echo "=============================="
echo ""

log_feature "🎯 Professional Trust Signals:"
echo "   • Clean, minimal design language"
echo "   • Consistent spacing and typography"
echo "   • Professional color palette (blacks, grays)"
echo "   • Subtle shadows and borders"
echo "   • Enterprise-grade visual hierarchy"
echo ""

log_feature "🔧 Vercel-Inspired Elements:"
echo "   • Monospace fonts for code/secrets"
echo "   • Clean button styles with hover states"
echo "   • Minimal, functional navigation"
echo "   • Card-based layout with subtle borders"
echo "   • Professional table designs"
echo ""

log_feature "💼 Trust & Credibility:"
echo "   • Familiar design patterns from trusted platforms"
echo "   • Clean, uncluttered interface"
echo "   • Professional typography (Inter font)"
echo "   • Consistent visual language"
echo "   • Enterprise-ready appearance"
echo ""

log_feature "📱 Modern UX:"
echo "   • Responsive design for all devices"
echo "   • Smooth transitions and interactions"
echo "   • Clear visual feedback"
echo "   • Intuitive navigation patterns"
echo "   • Accessible color contrasts"
echo ""

echo "🌟 Why This Increases Trust"
echo "=========================="
echo ""
log_success "🏢 Enterprise Familiarity:"
echo "   • Users recognize the professional Vercel aesthetic"
echo "   • Familiar patterns reduce cognitive load"
echo "   • Clean design suggests reliable engineering"
echo ""

log_success "🔒 Security Perception:"
echo "   • Professional appearance implies security focus"
echo "   • Clean interface suggests attention to detail"
echo "   • Familiar patterns increase user confidence"
echo ""

log_success "⚡ Performance Impression:"
echo "   • Fast, responsive interface"
echo "   • Minimal design suggests optimized performance"
echo "   • Clean code architecture visible in UI"
echo ""

echo "🚀 Access Your Professional Dashboard"
echo "===================================="
echo ""
log_success "Your Keyorix dashboard now has Vercel-level professionalism!"
echo ""
echo "🌐 Dashboard URL: http://localhost:8080/"
echo ""
echo "✨ Key Improvements:"
echo "   • Professional, trustworthy appearance"
echo "   • Clean, minimal design language"
echo "   • Enterprise-ready visual hierarchy"
echo "   • Familiar, confidence-inspiring patterns"
echo ""

# Show current system status
log_info "System Status:"
HEALTH_DATA=$(curl -s http://localhost:8080/health)
echo "   Status: $(echo $HEALTH_DATA | grep -o '"status":"[^"]*"' | cut -d'"' -f4)"
echo "   Version: $(echo $HEALTH_DATA | grep -o '"version":"[^"]*"' | cut -d'"' -f4)"
echo ""

log_success "🎉 Vercel-style deployment complete!"
echo ""
echo "Your secret management platform now has the professional,"
echo "trustworthy appearance that users expect from enterprise tools."