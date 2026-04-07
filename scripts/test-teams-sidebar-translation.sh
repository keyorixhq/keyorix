#!/bin/bash

echo "🔍 Testing Teams Sidebar Translation Fix..."
echo "=========================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if Teams sidebar link uses correct onclick
echo ""
echo "📋 Checking Teams Sidebar Link:"
if grep -q "onclick=\"showTab('team-settings')\".*Teams" web/dist/index.html; then
    echo "✅ Teams sidebar link uses showTab('team-settings')"
else
    echo "❌ Teams sidebar link has incorrect onclick"
fi

# Check if team-settings-tab translations exist
echo ""
echo "🌐 Checking team-settings-tab Translations:"

# English
if grep -q "'team-settings-tab': 'Teams'" web/dist/index.html; then
    echo "✅ English translation: 'team-settings-tab': 'Teams'"
else
    echo "❌ English translation missing for team-settings-tab"
fi

# Spanish
if grep -q "'team-settings-tab': 'Equipos'" web/dist/index.html; then
    echo "✅ Spanish translation: 'team-settings-tab': 'Equipos'"
else
    echo "❌ Spanish translation missing for team-settings-tab"
fi

# French
if grep -q "'team-settings-tab': 'Équipes'" web/dist/index.html; then
    echo "✅ French translation: 'team-settings-tab': 'Équipes'"
else
    echo "❌ French translation missing for team-settings-tab"
fi

# Russian
if grep -q "'team-settings-tab': 'Команды'" web/dist/index.html; then
    echo "✅ Russian translation: 'team-settings-tab': 'Команды'"
else
    echo "❌ Russian translation missing for team-settings-tab"
fi

# Check if Teams page title has correct ID
echo ""
echo "📄 Checking Teams Page Title:"
if grep -q 'id="teams-rbac-title".*Teams & RBAC' web/dist/index.html; then
    echo "✅ Teams page title has correct ID: teams-rbac-title"
else
    echo "❌ Teams page title missing correct ID"
fi

# Check if teams-rbac-title translations exist
echo ""
echo "🌐 Checking teams-rbac-title Translations:"

# Spanish
if grep -q "'teams-rbac-title': 'Equipos y RBAC'" web/dist/index.html; then
    echo "✅ Spanish page title: 'teams-rbac-title': 'Equipos y RBAC'"
else
    echo "❌ Spanish page title translation missing"
fi

# French
if grep -q "'teams-rbac-title': 'Équipes et RBAC'" web/dist/index.html; then
    echo "✅ French page title: 'teams-rbac-title': 'Équipes et RBAC'"
else
    echo "❌ French page title translation missing"
fi

# Russian
if grep -q "'teams-rbac-title': 'Команды и RBAC'" web/dist/index.html; then
    echo "✅ Russian page title: 'teams-rbac-title': 'Команды и RBAC'"
else
    echo "❌ Russian page title translation missing"
fi

echo ""
echo "🎯 Teams Translation Fix Summary:"
echo "================================="
echo "✅ Teams sidebar link: showTab('team-settings') → team-settings-tab"
echo "✅ Sidebar translations: Teams → Equipos (ES), Équipes (FR), Команды (RU)"
echo "✅ Page title translations: Teams & RBAC → Equipos y RBAC (ES)"
echo ""
echo "🚀 Test the fix:"
echo "================"
echo "1. Open web/dist/index.html in browser"
echo "2. Hard refresh (Ctrl+F5 or Cmd+Shift+R)"
echo "3. Switch to Spanish language"
echo "4. Check sidebar: 'Teams' should show 'Equipos'"
echo "5. Click Teams link: page title should show 'Equipos y RBAC'"
echo ""
echo "🔧 If still not working:"
echo "======================="
echo "1. Clear browser cache completely"
echo "2. Open developer tools (F12)"
echo "3. Run in console: applyTranslations('es')"
echo "4. Check for JavaScript errors"
echo ""
echo "✨ Teams sidebar translation fix completed!"