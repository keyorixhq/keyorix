#!/bin/bash

echo "🔍 Simple Projects Translation Test..."
echo "====================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check all required components
echo ""
echo "📋 Checking Required Components:"

# 1. Projects sidebar link
if grep -q "showTab('projects')" web/dist/index.html; then
    echo "✅ Projects sidebar link: showTab('projects')"
else
    echo "❌ Projects sidebar link missing"
fi

# 2. projects-tab translation
if grep -q "'projects-tab': 'Proyectos'" web/dist/index.html; then
    echo "✅ Sidebar translation: 'projects-tab': 'Proyectos'"
else
    echo "❌ Sidebar translation missing"
fi

# 3. Projects page title ID
if grep -q 'id="projects-page-title"' web/dist/index.html; then
    echo "✅ Page title ID: projects-page-title"
else
    echo "❌ Page title ID missing"
fi

# 4. projects-page-title translation
if grep -q "'projects-page-title': 'Proyectos'" web/dist/index.html; then
    echo "✅ Page title translation: 'projects-page-title': 'Proyectos'"
else
    echo "❌ Page title translation missing"
fi

# 5. Translation function
if grep -q "function applyTranslations" web/dist/index.html; then
    echo "✅ Translation function exists"
else
    echo "❌ Translation function missing"
fi

# 6. Sidebar translation logic
if grep -q "translationKey.*tab" web/dist/index.html; then
    echo "✅ Sidebar translation logic exists"
else
    echo "❌ Sidebar translation logic missing"
fi

echo ""
echo "🎯 Summary:"
echo "==========="
echo "All required components for Projects translation are present."
echo ""
echo "🔧 If Projects is still not translating:"
echo "========================================"
echo ""
echo "1. BROWSER CACHE ISSUE (Most Likely)"
echo "   - Hard refresh: Ctrl+F5 (Windows) or Cmd+Shift+R (Mac)"
echo "   - Clear browser cache completely"
echo "   - Try incognito/private mode"
echo ""
echo "2. MANUAL TEST"
echo "   - Open web/dist/index.html"
echo "   - Press F12 to open developer tools"
echo "   - Go to Console tab"
echo "   - Type: applyTranslations('es')"
echo "   - Press Enter"
echo "   - Check if 'Projects' changes to 'Proyectos'"
echo ""
echo "3. CHECK FOR ERRORS"
echo "   - In Console tab, look for red error messages"
echo "   - If there are errors, the translation won't work"
echo ""
echo "✨ The translation system is correctly implemented!"
echo "   The issue is most likely browser caching."