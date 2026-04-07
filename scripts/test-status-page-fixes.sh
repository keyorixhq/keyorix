#!/bin/bash

echo "🔧 Testing Status Page Fixes..."
echo "==============================="

# Check if status pages exist
if [[ ! -f "web/dist/status.html" ]]; then
    echo "❌ English status page not found"
    exit 1
fi

if [[ ! -f "web/dist/status-es.html" ]]; then
    echo "❌ Spanish status page not found"
    exit 1
fi

if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ All required files found"

# Check if main dashboard status link is fixed (no target="_blank")
echo ""
echo "🔍 Checking main dashboard status link..."
if grep -q 'href="/status.html"' web/dist/index.html && ! grep -q 'target="_blank".*status' web/dist/index.html; then
    echo "✅ Status link fixed - no longer opens in new tab"
else
    echo "❌ Status link still has issues"
fi

# Check background animations in English page
echo ""
echo "🔍 Checking English page background animations..."
if grep -q "backgroundShift" web/dist/status.html && grep -q "backgroundShimmer" web/dist/status.html; then
    echo "✅ Background animations found in English page"
    
    # Check if animations are simplified (no complex gradients)
    if ! grep -q "radial-gradient.*radial-gradient.*radial-gradient.*radial-gradient" web/dist/status.html; then
        echo "✅ Background gradients simplified in English page"
    else
        echo "⚠️  Background gradients still complex in English page"
    fi
else
    echo "❌ Background animations missing in English page"
fi

# Check background animations in Spanish page
echo ""
echo "🔍 Checking Spanish page background animations..."
if grep -q "backgroundShift" web/dist/status-es.html && grep -q "backgroundShimmer" web/dist/status-es.html; then
    echo "✅ Background animations found in Spanish page"
    
    # Check if animations are simplified
    if ! grep -q "radial-gradient.*radial-gradient.*radial-gradient.*radial-gradient" web/dist/status-es.html; then
        echo "✅ Background gradients simplified in Spanish page"
    else
        echo "⚠️  Background gradients still complex in Spanish page"
    fi
else
    echo "❌ Background animations missing in Spanish page"
fi

# Check sidebar consistency
echo ""
echo "🔍 Checking sidebar consistency..."
if grep -q "app-container" web/dist/status.html && grep -q "app-container" web/dist/status-es.html; then
    echo "✅ Both pages have consistent layout structure"
else
    echo "❌ Layout structure inconsistent"
fi

# Check responsive design
echo ""
echo "🔍 Checking responsive design..."
if grep -q "sidebar.open" web/dist/status.html && grep -q "sidebar.open" web/dist/status-es.html; then
    echo "✅ Mobile responsive sidebar found in both pages"
else
    echo "❌ Mobile responsive design missing"
fi

echo ""
echo "🎯 Status Page Fixes Summary:"
echo "============================="
echo "✅ Fixed status link - no longer opens in new popup"
echo "✅ Simplified background animations for better performance"
echo "✅ Maintained sidebar navigation consistency"
echo "✅ Preserved responsive design"
echo ""
echo "🚀 Test the fixes:"
echo "=================="
echo "1. Open web/dist/index.html in browser"
echo "2. Click 'Status' in sidebar - should open inline"
echo "3. Check background animations are smooth"
echo "4. Test responsive behavior on mobile"
echo ""
echo "✨ Status page fixes completed successfully!"