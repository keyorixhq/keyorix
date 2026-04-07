#!/bin/bash

echo "🔍 Diagnosing Translation Issues..."
echo "=================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check for specific untranslated elements you mentioned
echo ""
echo "🔍 Checking specific elements mentioned..."

# Check for Teams page title
echo ""
echo "📋 Teams Page Title:"
if grep -n "Teams & RBAC" web/dist/index.html | head -5; then
    echo "Found 'Teams & RBAC' text - checking if it has translation ID..."
    if grep -q 'id="teams-rbac-title".*Teams & RBAC' web/dist/index.html; then
        echo "✅ Teams page title has translation ID"
    else
        echo "❌ Teams page title missing translation ID"
    fi
else
    echo "No 'Teams & RBAC' text found"
fi

# Check for RBAC labels
echo ""
echo "📊 RBAC Summary Labels:"
rbac_elements=(
    "Total Users"
    "Active Teams" 
    "Total Roles"
    "Permissions"
)

for element in "${rbac_elements[@]}"; do
    echo "Checking: $element"
    if grep -n "$element" web/dist/index.html | head -3; then
        if grep -q "data-translate.*$element" web/dist/index.html; then
            echo "✅ '$element' has data-translate attribute"
        else
            echo "❌ '$element' missing data-translate attribute"
        fi
    else
        echo "❓ '$element' not found"
    fi
    echo ""
done

# Check system status
echo ""
echo "🖥️  System Status:"
if grep -n "All systems operational" web/dist/index.html | head -3; then
    if grep -q 'id="system-status".*All systems operational' web/dist/index.html; then
        echo "✅ System status has translation ID"
    else
        echo "❌ System status missing translation ID"
    fi
else
    echo "No 'All systems operational' text found"
fi

# Check translation function
echo ""
echo "🔧 Translation Function Check:"
if grep -q "applyTranslations" web/dist/index.html; then
    echo "✅ Translation function exists"
    
    if grep -q "data-translate" web/dist/index.html && grep -q "querySelectorAll.*data-translate" web/dist/index.html; then
        echo "✅ Translation function handles data-translate attributes"
    else
        echo "❌ Translation function may not handle data-translate attributes"
    fi
else
    echo "❌ Translation function missing"
fi

# Check if translations are being applied on language change
echo ""
echo "🌐 Language Change Handler:"
if grep -q "changeLanguage" web/dist/index.html; then
    echo "✅ Language change function exists"
    
    if grep -q "applyTranslations.*lang" web/dist/index.html; then
        echo "✅ Language change calls translation function"
    else
        echo "❌ Language change may not call translation function"
    fi
else
    echo "❌ Language change function missing"
fi

echo ""
echo "🎯 Diagnostic Summary:"
echo "====================="
echo "If you're still seeing untranslated content, try:"
echo "1. Hard refresh the browser (Ctrl+F5 or Cmd+Shift+R)"
echo "2. Clear browser cache"
echo "3. Check browser console for JavaScript errors"
echo "4. Verify the language switcher is working"
echo ""
echo "🚀 Quick Test Steps:"
echo "==================="
echo "1. Open web/dist/index.html"
echo "2. Open browser developer tools (F12)"
echo "3. Go to Console tab"
echo "4. Switch to Spanish language"
echo "5. Check if any errors appear in console"
echo "6. Manually run: applyTranslations('es')"
echo ""
echo "✨ Diagnostic completed!"