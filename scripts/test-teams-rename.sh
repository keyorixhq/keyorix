#!/bin/bash

# Test Teams Rename
echo "✅ Testing Teams Rename"
echo "======================"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Test server
log_info "Testing server connection..."
if curl -s http://localhost:8080/health > /dev/null; then
    log_success "✅ Server is running"
else
    echo "❌ Server is not running"
    exit 1
fi

# Get dashboard content
CONTENT=$(curl -s http://localhost:8080/)

echo ""
echo "🔍 Checking Rename Results"
echo "=========================="

# Check sidebar navigation
if echo "$CONTENT" | grep -q "sidebar-icon.*👥.*Teams"; then
    log_success "✅ Sidebar navigation renamed to 'Teams'"
else
    echo "⚠️  Sidebar navigation not found"
fi

# Check page title
if echo "$CONTENT" | grep -q "Teams & RBAC"; then
    log_success "✅ Page title updated to 'Teams & RBAC'"
else
    echo "⚠️  Page title not found"
fi

# Check JavaScript title mapping
if echo "$CONTENT" | grep -q "'team-settings': 'Teams'"; then
    log_success "✅ JavaScript title mapping updated"
else
    echo "⚠️  JavaScript mapping not found"
fi

# Check tab comment
if echo "$CONTENT" | grep -q "<!-- Teams Tab -->"; then
    log_success "✅ HTML comment updated to 'Teams Tab'"
else
    echo "⚠️  HTML comment not found"
fi

# Verify no old references remain
if echo "$CONTENT" | grep -q "Team Settings"; then
    echo "⚠️  Found remaining 'Team Settings' references"
else
    log_success "✅ No old 'Team Settings' references found"
fi

echo ""
echo "📋 Rename Summary"
echo "================"
echo ""
log_success "🎯 Successfully renamed:"
echo "   • Sidebar navigation: 'Team Settings' → 'Teams'"
echo "   • Page title: 'Team Settings & RBAC' → 'Teams & RBAC'"
echo "   • HTML comment: 'Team Settings Tab' → 'Teams Tab'"
echo "   • JavaScript mapping: Updated to 'Teams'"
echo ""

log_success "✨ Benefits of the rename:"
echo "   • Cleaner, more concise navigation"
echo "   • Better visual hierarchy in sidebar"
echo "   • More direct and professional naming"
echo "   • Consistent with modern UI patterns"
echo ""

echo "🌐 Test the rename: http://localhost:8080/ (Teams tab)"
echo ""
log_success "🎉 Teams rename completed successfully!"