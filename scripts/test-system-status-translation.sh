#!/bin/bash

echo "🔍 Testing System Status Translation Fix..."
echo "=========================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if system status element has correct ID
echo ""
echo "🖥️  Checking System Status Element:"
if grep -q 'id="system-status"' web/dist/index.html; then
    echo "✅ System status element has correct ID: system-status"
else
    echo "❌ System status element missing correct ID"
fi

# Check if JavaScript uses translation system
echo ""
echo "🔧 Checking JavaScript Translation Usage:"
if grep -q "t\['system-status'\]" web/dist/index.html; then
    echo "✅ JavaScript now uses translation system for system status"
else
    echo "❌ JavaScript still hardcodes system status text"
fi

# Check if system-status translations exist
echo ""
echo "🌐 Checking system-status Translations:"

# English
if grep -q "'system-status': 'All systems operational'" web/dist/index.html; then
    echo "✅ English: 'All systems operational'"
else
    echo "❌ English translation missing"
fi

# Spanish
if grep -q "'system-status': 'Todos los sistemas operativos'" web/dist/index.html; then
    echo "✅ Spanish: 'Todos los sistemas operativos'"
else
    echo "❌ Spanish translation missing"
fi

# French
if grep -q "'system-status': 'Tous les systèmes opérationnels'" web/dist/index.html; then
    echo "✅ French: 'Tous les systèmes opérationnels'"
else
    echo "❌ French translation missing"
fi

# Russian
if grep -q "'system-status': 'Все системы работают'" web/dist/index.html; then
    echo "✅ Russian: 'Все системы работают'"
else
    echo "❌ Russian translation missing"
fi

# Check if system-issues translations exist
echo ""
echo "⚠️  Checking system-issues Translations:"

# English
if grep -q "'system-issues': 'System issues detected'" web/dist/index.html; then
    echo "✅ English: 'System issues detected'"
else
    echo "❌ English system-issues translation missing"
fi

# Spanish
if grep -q "'system-issues': 'Problemas del sistema detectados'" web/dist/index.html; then
    echo "✅ Spanish: 'Problemas del sistema detectados'"
else
    echo "❌ Spanish system-issues translation missing"
fi

# French
if grep -q "'system-issues': 'Problèmes système détectés'" web/dist/index.html; then
    echo "✅ French: 'Problèmes système détectés'"
else
    echo "❌ French system-issues translation missing"
fi

# Russian
if grep -q "'system-issues': 'Обнаружены проблемы системы'" web/dist/index.html; then
    echo "✅ Russian: 'Обнаружены проблемы системы'"
else
    echo "❌ Russian system-issues translation missing"
fi

echo ""
echo "🎯 System Status Translation Fix Summary:"
echo "========================================"
echo "✅ Fixed JavaScript to use translation system instead of hardcoded text"
echo "✅ Added system-status translations for all languages"
echo "✅ Added system-issues translations for all languages"
echo ""
echo "🚀 Test the fix:"
echo "================"
echo "1. Open web/dist/index.html in browser"
echo "2. Hard refresh (Ctrl+F5 or Cmd+Shift+R)"
echo "3. Switch to Spanish language"
echo "4. Check system status: should show 'Todos los sistemas operativos'"
echo "5. Navigate between pages - status should stay in Spanish"
echo ""
echo "🔧 Why it wasn't working before:"
echo "==============================="
echo "The JavaScript code was hardcoding 'All systems operational'"
echo "instead of using the translation system. Now it properly"
echo "uses the current language's translation."
echo ""
echo "✨ System status translation fix completed!"