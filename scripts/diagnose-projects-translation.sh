#!/bin/bash

echo "🔍 Comprehensive Projects Translation Diagnosis..."
echo "================================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check Projects sidebar link
echo ""
echo "📁 Checking Projects Sidebar Link:"
if grep -q "onclick=\"showTab('projects')\".*Projects" web/dist/index.html; then
    echo "✅ Projects sidebar link uses showTab('projects')"
    echo "   This should generate translation key: projects-tab"
else
    echo "❌ Projects sidebar link has incorrect onclick"
fi

# Check if projects-tab translation exists
echo ""
echo "🌐 Checking projects-tab Translation:"
if grep -q "'projects-tab': 'Proyectos'" web/dist/index.html; then
    echo "✅ Spanish sidebar translation: 'projects-tab': 'Proyectos'"
else
    echo "❌ Spanish sidebar translation missing"
fi

# Check Projects page title
echo ""
echo "📄 Checking Projects Page Title:"
if grep -q 'id="projects-page-title".*Projects' web/dist/index.html; then
    echo "✅ Projects page title has ID: projects-page-title"
else
    echo "❌ Projects page title missing ID"
fi

# Check if projects-page-title translation exists
echo ""
echo "🌐 Checking projects-page-title Translation:"
if grep -q "'projects-page-title': 'Proyectos'" web/dist/index.html; then
    echo "✅ Spanish page title translation: 'projects-page-title': 'Proyectos'"
else
    echo "❌ Spanish page title translation missing"
fi

# Check translation function
echo ""
echo "🔧 Checking Translation Function:"
if grep -q "applyTranslations.*function" web/dist/index.html; then
    echo "✅ Translation function exists"
    
    # Check if it handles both ID and data-translate
    if grep -q "getElementById.*textContent" web/dist/index.html && grep -q "querySelectorAll.*data-translate" web/dist/index.html; then
        echo "✅ Translation function handles both ID and data-translate elements"
    else
        echo "❌ Translation function may not handle all element types"
    fi
else
    echo "❌ Translation function missing"
fi

# Check sidebar translation logic
echo ""
echo "🔄 Checking Sidebar Translation Logic:"
if grep -q "sidebar-item.*onclick.*showTab" web/dist/index.html && grep -q "translationKey.*tab" web/dist/index.html; then
    echo "✅ Sidebar translation logic exists"
    echo "   Pattern: showTab('X') → X + '-tab' → translation key"
else
    echo "❌ Sidebar translation logic missing or broken"
fi

echo ""
echo "🎯 Diagnosis Summary:"
echo "===================="
echo "If Projects is still not translating, the issue is likely:"
echo ""
echo "1. 🔄 BROWSER CACHE - Most common cause"
echo "   Solution: Hard refresh (Ctrl+F5) or clear cache"
echo ""
echo "2. 🔧 JAVASCRIPT ERRORS - Check browser console"
echo "   Solution: Open F12, check Console tab for errors"
echo ""
echo "3. 🌐 LANGUAGE NOT APPLIED - Translation function not called"
echo "   Solution: Manually run applyTranslations('es') in console"
echo ""
echo "🚀 Step-by-step test:"
echo "===================="
echo "1. Open web/dist/index.html"
echo "2. Open browser developer tools (F12)"
echo "3. Go to Console tab"
echo "4. Run: applyTranslations('es')"
echo "5. Check if 'Projects' changes to 'Proyectos' in sidebar"
echo "6. Click Projects link and check if page title changes"
echo ""
echo "If step 4 works, the issue is browser cache."
echo "If step 4 doesn't work, there's a JavaScript error."
echo ""
echo "✨ Projects translation diagnosis completed!"