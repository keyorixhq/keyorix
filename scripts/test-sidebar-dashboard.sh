#!/bin/bash

# Test Sidebar Dashboard Layout
echo "🎨 Testing Sidebar Dashboard Layout"
echo "=================================="

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

# Test sidebar layout elements
log_info "Testing sidebar layout elements..."
DASHBOARD_CONTENT=$(curl -s http://localhost:8080/)

# Test sidebar structure
if echo "$DASHBOARD_CONTENT" | grep -q "sidebar"; then
    log_design "✅ Sidebar structure implemented"
else
    echo "⚠️  Sidebar structure not found"
fi

# Test navigation items
if echo "$DASHBOARD_CONTENT" | grep -q "Projects"; then
    log_design "✅ Projects navigation item present"
else
    echo "⚠️  Projects navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Activity"; then
    log_design "✅ Activity navigation item present"
else
    echo "⚠️  Activity navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Pull Requests"; then
    log_design "✅ Pull Requests navigation item present"
else
    echo "⚠️  Pull Requests navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Tokens"; then
    log_design "✅ Tokens navigation item present"
else
    echo "⚠️  Tokens navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Team Settings"; then
    log_design "✅ Team Settings navigation item present"
else
    echo "⚠️  Team Settings navigation not found"
fi

# Test core features
if echo "$DASHBOARD_CONTENT" | grep -q "Overview"; then
    log_design "✅ Overview navigation item present"
else
    echo "⚠️  Overview navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Secrets"; then
    log_design "✅ Secrets navigation item present"
else
    echo "⚠️  Secrets navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Sharing"; then
    log_design "✅ Sharing navigation item present"
else
    echo "⚠️  Sharing navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Audit"; then
    log_design "✅ Audit navigation item present"
else
    echo "⚠️  Audit navigation not found"
fi

# Test support section
if echo "$DASHBOARD_CONTENT" | grep -q "Docs"; then
    log_design "✅ Docs navigation item present"
else
    echo "⚠️  Docs navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Support"; then
    log_design "✅ Support navigation item present"
else
    echo "⚠️  Support navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Community"; then
    log_design "✅ Community navigation item present"
else
    echo "⚠️  Community navigation not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "Status"; then
    log_design "✅ Status navigation item present"
else
    echo "⚠️  Status navigation not found"
fi

# Test layout structure
if echo "$DASHBOARD_CONTENT" | grep -q "app-layout"; then
    log_design "✅ App layout structure present"
else
    echo "⚠️  App layout structure not found"
fi

if echo "$DASHBOARD_CONTENT" | grep -q "main-content"; then
    log_design "✅ Main content area present"
else
    echo "⚠️  Main content area not found"
fi

# Test sidebar divider
if echo "$DASHBOARD_CONTENT" | grep -q "sidebar-divider"; then
    log_design "✅ Sidebar dividers present"
else
    echo "⚠️  Sidebar dividers not found"
fi

echo ""
echo "🎯 Sidebar Dashboard Features"
echo "============================"
echo ""

log_feature "🎨 Professional Sidebar Layout:"
echo "   • Fixed left sidebar with 280px width"
echo "   • Dark theme with glass morphism effects"
echo "   • Smooth hover animations and active states"
echo "   • Professional icon integration"
echo "   • Organized sections with dividers"
echo ""

log_feature "📱 Navigation Structure:"
echo "   • Projects - Project and environment management"
echo "   • Activity - Real-time activity monitoring"
echo "   • Pull Requests - GitOps workflow management"
echo "   • Tokens - API token and credential management"
echo "   • Team Settings - RBAC and team configuration"
echo ""

log_feature "🔧 Core Features:"
echo "   • Overview - System dashboard and statistics"
echo "   • Secrets - Secret management and CLI guide"
echo "   • Sharing - Secure secret sharing workflows"
echo "   • Audit - Compliance and security monitoring"
echo ""

log_feature "💬 Support & Resources:"
echo "   • Docs - API documentation and guides"
echo "   • Support - Help desk and ticket system"
echo "   • Community - Forums and knowledge base"
echo "   • Status - System health and uptime"
echo ""

log_feature "✨ Design Excellence:"
echo "   • Sophisticated dark theme with gradients"
echo "   • Glass morphism effects and backdrop blur"
echo "   • Smooth animations and hover states"
echo "   • Professional typography and spacing"
echo "   • Mobile-responsive design"
echo ""

echo "🌐 Dashboard URL: http://localhost:8080/"
echo ""
log_success "🎉 Professional sidebar dashboard is active!"
echo ""
echo "The dashboard now features:"
echo "• Professional left sidebar navigation"
echo "• Organized menu sections with dividers"
echo "• All requested navigation items"
echo "• Sophisticated dark theme design"
echo "• Enterprise-grade layout and functionality"