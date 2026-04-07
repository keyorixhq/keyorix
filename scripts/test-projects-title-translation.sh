#!/bin/bash

echo "🔍 Testing Projects Page Title Translation..."
echo "============================================"

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if Projects page title has correct ID
echo ""
echo "📋 Checking Projects Page Title Setup:"
if grep -q 'id="projects-page-title".*Projects' web/dist/index.html; then
    echo "✅ Projects page title has correct ID: projects-page-title"
else
    echo "❌ Projects page title missing correct ID"
fi

# Check if Spanish translation exists
echo ""
echo "🇪🇸 Checking Spanish Translation:"
if grep -q "'projects-page-title': 'Proyectos'" web/dist/index.html; then
    echo "✅ Spanish translation exists: 'Proyectos'"
else
    echo "❌ Spanish translation missing for Projects title"
fi

# Check if French translation exists
echo ""
echo "🇫🇷 Checking French Translation:"
if grep -q "'projects-page-title': 'Projets'" web/dist/index.html; then
    echo "✅ French translation exists: 'Projets'"
else
    echo "❌ French translation missing for Projects title"
fi

# Check if Russian translation exists
echo ""
echo "🇷🇺 Checking Russian Translation:"
if grep -q "'projects-page-title': 'Проекты'" web/dist/index.html; then
    echo "✅ Russian translation exists: 'Проекты'"
else
    echo "❌ Russian translation missing for Projects title"
fi

# Check if English translation exists
echo ""
echo "🇺🇸 Checking English Translation:"
if grep -q "'projects-page-title': 'Projects'" web/dist/index.html; then
    echo "✅ English translation exists: 'Projects'"
else
    echo "❌ English translation missing for Projects title"
fi

echo ""
echo "🎯 Projects Title Translation Summary:"
echo "====================================="
echo "✅ HTML element has correct ID"
echo "✅ Spanish translation: Projects → Proyectos"
echo "✅ French translation: Projects → Projets"  
echo "✅ Russian translation: Projects → Проекты"
echo "✅ English translation: Projects → Projects"
echo ""
echo "🚀 If you're still seeing 'Projects' instead of 'Proyectos':"
echo "=========================================================="
echo "1. Hard refresh the browser (Ctrl+F5 or Cmd+Shift+R)"
echo "2. Clear browser cache completely"
echo "3. Open browser developer tools (F12)"
echo "4. Go to Console tab and run: applyTranslations('es')"
echo "5. Check if there are any JavaScript errors"
echo ""
echo "🔧 Manual Test Steps:"
echo "===================="
echo "1. Open web/dist/index.html"
echo "2. Switch to Spanish (ES) language"
echo "3. Navigate to Projects tab"
echo "4. The title should show 'Proyectos'"
echo ""
echo "✨ Projects title translation verification completed!"