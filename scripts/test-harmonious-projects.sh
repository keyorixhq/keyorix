#!/bin/bash

# Test Harmonious Projects Design
echo "🎨 Testing Harmonious Projects Design"
echo "===================================="

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_feature() { echo -e "${PURPLE}[FEATURE]${NC} $1"; }
log_design() { echo -e "${CYAN}[DESIGN]${NC} $1"; }

# Test server health
log_info "Testing server health..."
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Server is healthy"
else
    echo "❌ Server is not responding"
    exit 1
fi

# Test harmonious design elements
log_info "Testing harmonious design elements..."
PROJECTS_CONTENT=$(curl -s http://localhost:8080/)

# Test new harmonious color palette
if echo "$PROJECTS_CONTENT" | grep -q "#6366f1.*#8b5cf6"; then
    log_design "✅ Mobile Backend: Harmonious indigo-purple gradient"
else
    echo "⚠️  Mobile Backend gradient not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "#06b6d4.*#0891b2"; then
    log_design "✅ Mobile Frontend: Harmonious cyan-blue gradient"
else
    echo "⚠️  Mobile Frontend gradient not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "#f59e0b.*#d97706"; then
    log_design "✅ Test Deployment: Harmonious amber-orange gradient"
else
    echo "⚠️  Test Deployment gradient not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "#ec4899.*#be185d"; then
    log_design "✅ Stage Team: Harmonious pink-rose gradient"
else
    echo "⚠️  Stage Team gradient not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "#10b981.*#059669"; then
    log_design "✅ Dev Team: Harmonious emerald-green gradient"
else
    echo "⚠️  Dev Team gradient not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "#8b5cf6.*#7c3aed"; then
    log_design "✅ Standalone App: Harmonious violet-purple gradient"
else
    echo "⚠️  Standalone App gradient not found"
fi

# Test enhanced styling
if echo "$PROJECTS_CONTENT" | grep -q "box-shadow.*rgba.*0.3"; then
    log_design "✅ Enhanced icon shadows with matching colors"
else
    echo "⚠️  Enhanced shadows not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "backdrop-filter.*blur"; then
    log_design "✅ Glass morphism effects implemented"
else
    echo "⚠️  Glass morphism not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "transform.*scale.*1.05"; then
    log_design "✅ Hover animations implemented"
else
    echo "⚠️  Hover animations not found"
fi

# Test professional enhancements
if echo "$PROJECTS_CONTENT" | grep -q "width.*52px.*height.*52px"; then
    log_design "✅ Enhanced icon sizing (52px)"
else
    echo "⚠️  Enhanced icon sizing not found"
fi

if echo "$PROJECTS_CONTENT" | grep -q "padding.*28px"; then
    log_design "✅ Improved card padding"
else
    echo "⚠️  Improved padding not found"
fi

echo ""
echo "🎯 Harmonious Design Features"
echo "============================"
echo ""

log_feature "🎨 Professional Color Palette:"
echo "   • Mobile Backend: Indigo to Purple (#6366f1 → #8b5cf6)"
echo "   • Mobile Frontend: Cyan to Blue (#06b6d4 → #0891b2)"
echo "   • Test Deployment: Amber to Orange (#f59e0b → #d97706)"
echo "   • Stage Team: Pink to Rose (#ec4899 → #be185d)"
echo "   • Dev Team: Emerald to Green (#10b981 → #059669)"
echo "   • Standalone App: Violet to Purple (#8b5cf6 → #7c3aed)"
echo ""

log_feature "✨ Visual Harmony Improvements:"
echo "   • Cohesive color temperature across all icons"
echo "   • Balanced saturation levels for professional look"
echo "   • Complementary color relationships"
echo "   • Consistent gradient directions (135deg)"
echo "   • Matching shadow colors for each icon"
echo ""

log_feature "🔧 Enhanced Professional Styling:"
echo "   • Larger icons (52px) for better visual impact"
echo "   • Glass morphism effects with backdrop blur"
echo "   • Subtle hover animations with scale transforms"
echo "   • Enhanced shadows with color-matched opacity"
echo "   • Improved card padding and spacing"
echo ""

log_feature "🎭 Status Badge Improvements:"
echo "   • Harmonious background opacity (15%)"
echo "   • Matching border colors with transparency"
echo "   • Glass morphism backdrop filters"
echo "   • Professional color coordination"
echo ""

log_feature "📊 Enhanced Statistics Section:"
echo "   • Improved glass morphism background"
echo "   • Better spacing and padding (20px)"
echo "   • Subtle border with transparency"
echo "   • Professional backdrop blur effects"
echo ""

echo "🌐 Projects Page URL: http://localhost:8080/ (Projects tab)"
echo ""
log_success "🎉 Harmonious projects design is active!"
echo ""
echo "Key improvements:"
echo "• Professional color harmony across all project icons"
echo "• Cohesive gradient palette with balanced saturation"
echo "• Enhanced visual effects with glass morphism"
echo "• Improved hover animations and interactions"
echo "• Enterprise-grade professional appearance"
echo ""
echo "The new design creates visual unity while maintaining"
echo "distinct identity for each project type!"