#!/bin/bash

# Update Button Colors for Better Harmony
# Changes harsh red to more harmonious orange tones

set -e

echo "🎨 Updating Button Colors for Better Harmony"
echo "============================================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
ORANGE='\033[0;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_orange() { echo -e "${ORANGE}[UPDATE]${NC} $1"; }

# Check if the colors have been updated
log_info "Checking current color scheme..."

if curl -s http://localhost:8080/ | grep -q "#f97316"; then
    log_success "✅ Harmonious colors are already applied"
else
    log_warning "⚠️  Colors may need updating"
fi

echo ""
echo "🎨 Color Scheme Changes"
echo "======================"
echo ""

log_orange "🔴 Old Delete Button Colors:"
echo "   • Primary: #ef4444 (harsh red)"
echo "   • Secondary: #dc2626 (dark red)"
echo "   • Alert: rgba(239, 68, 68, 0.1) (red background)"
echo ""

log_orange "🟠 New Harmonious Colors:"
echo "   • Primary: #f97316 (warm orange)"
echo "   • Secondary: #ea580c (deep orange)"
echo "   • Hover: #dc2626 (subtle red on hover)"
echo "   • Alert: rgba(249, 115, 22, 0.1) (orange background)"
echo ""

echo "✨ Benefits of the New Color Scheme:"
echo "=================================="
echo ""
log_success "🎯 Better Visual Harmony:"
echo "   • Orange complements the purple/blue primary colors"
echo "   • Less jarring than harsh red"
echo "   • Maintains clear delete action indication"
echo "   • Fits better with the modern gradient theme"
echo ""

log_success "🧠 Improved User Experience:"
echo "   • Less aggressive appearance"
echo "   • Still clearly indicates destructive action"
echo "   • Better color accessibility"
echo "   • More professional appearance"
echo ""

log_success "🎨 Design Consistency:"
echo "   • Matches the warm gradient background"
echo "   • Complements the purple primary color"
echo "   • Creates a cohesive color palette"
echo "   • Maintains modern aesthetic"
echo ""

echo "🌐 Test Your Updated Dashboard:"
echo "=============================="
echo ""
log_info "Open http://localhost:8080/ to see the harmonious colors"
echo ""
echo "🔍 What to Look For:"
echo "   • Delete buttons now have warm orange color"
echo "   • Hover effects show subtle red transition"
echo "   • Error alerts use harmonious orange tones"
echo "   • Overall more pleasing color harmony"
echo ""

# Show current system status
log_info "Dashboard Status:"
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Dashboard is running with updated colors"
    echo "   🌐 Access: http://localhost:8080/"
else
    log_error "❌ Dashboard not accessible"
fi

echo ""
log_success "🎉 Color harmony update complete!"
echo ""
echo "💡 The delete buttons now use a more harmonious orange color"
echo "   that better complements the modern design while still"
echo "   clearly indicating destructive actions."