#!/bin/bash

echo "🌐 Testing Teams & RBAC Translation Fixes..."
echo "============================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if page title and description have IDs
echo ""
echo "🔍 Checking page header translations..."
if grep -q 'id="teams-rbac-title"' web/dist/index.html; then
    echo "✅ Teams & RBAC title has ID"
else
    echo "❌ Teams & RBAC title missing ID"
fi

if grep -q 'id="teams-rbac-description"' web/dist/index.html; then
    echo "✅ Teams & RBAC description has ID"
else
    echo "❌ Teams & RBAC description missing ID"
fi

# Check if common elements have data-translate attributes
echo ""
echo "🔍 Checking common element translations..."
common_elements=(
    "active-status"
    "members-label"
    "roles-label"
    "manage-button"
    "read-permission"
    "write-permission"
    "share-permission"
    "admin-permission"
    "limited-permission"
)

missing_elements=0
for element in "${common_elements[@]}"; do
    if grep -q "data-translate=\"$element\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $element"
    else
        echo "❌ Missing data-translate for: $element"
        ((missing_elements++))
    fi
done

# Check Spanish translations
echo ""
echo "🔍 Checking Spanish translations..."
spanish_translations=(
    "Equipos y RBAC"
    "Gestiona equipos, roles y permisos"
    "Activo"
    "Miembros"
    "Roles"
    "Gestionar"
    "Leer"
    "Escribir"
    "Compartir"
    "Administrador"
    "Limitado"
)

missing_spanish=0
for translation in "${spanish_translations[@]}"; do
    if grep -q "$translation" web/dist/index.html; then
        echo "✅ Found Spanish translation: $translation"
    else
        echo "❌ Missing Spanish translation: $translation"
        ((missing_spanish++))
    fi
done

# Check French translations
echo ""
echo "🔍 Checking French translations..."
french_translations=(
    "Équipes et RBAC"
    "Gérez les équipes, rôles et permissions"
    "Actif"
    "Membres"
    "Rôles"
    "Gérer"
    "Lire"
    "Écrire"
    "Partager"
    "Administrateur"
    "Limité"
)

missing_french=0
for translation in "${french_translations[@]}"; do
    if grep -q "$translation" web/dist/index.html; then
        echo "✅ Found French translation: $translation"
    else
        echo "❌ Missing French translation: $translation"
        ((missing_french++))
    fi
done

# Check Russian translations
echo ""
echo "🔍 Checking Russian translations..."
russian_translations=(
    "Команды и RBAC"
    "Управляйте командами, ролями и разрешениями"
    "Активный"
    "Участники"
    "Роли"
    "Управлять"
    "Чтение"
    "Запись"
    "Общий доступ"
    "Администратор"
    "Ограниченный"
)

missing_russian=0
for translation in "${russian_translations[@]}"; do
    if grep -q "$translation" web/dist/index.html; then
        echo "✅ Found Russian translation: $translation"
    else
        echo "❌ Missing Russian translation: $translation"
        ((missing_russian++))
    fi
done

# Check if translation function was updated
echo ""
echo "🔍 Checking translation function updates..."
if grep -q "data-translate" web/dist/index.html && grep -q "querySelectorAll.*data-translate" web/dist/index.html; then
    echo "✅ Translation function updated to handle data-translate attributes"
else
    echo "❌ Translation function not updated for data-translate attributes"
fi

echo ""
echo "🎯 Teams & RBAC Translation Fix Summary:"
echo "========================================"
echo "Common elements: $((${#common_elements[@]} - missing_elements))/${#common_elements[@]} have data-translate"
echo "Spanish translations: $((${#spanish_translations[@]} - missing_spanish))/${#spanish_translations[@]} found"
echo "French translations: $((${#french_translations[@]} - missing_french))/${#french_translations[@]} found"
echo "Russian translations: $((${#russian_translations[@]} - missing_russian))/${#russian_translations[@]} found"

if [[ $missing_elements -eq 0 && $missing_spanish -eq 0 && $missing_french -eq 0 && $missing_russian -eq 0 ]]; then
    echo ""
    echo "✅ All Teams & RBAC translation fixes implemented successfully!"
    echo ""
    echo "🚀 Test the fixes:"
    echo "=================="
    echo "1. Open web/dist/index.html in browser"
    echo "2. Navigate to Teams tab"
    echo "3. Switch to Spanish language"
    echo "4. Verify all content is translated:"
    echo "   - Page title: 'Equipos y RBAC'"
    echo "   - Status labels: 'Activo'"
    echo "   - Stat labels: 'Miembros', 'Roles'"
    echo "   - Buttons: 'Gestionar'"
    echo "   - Permissions: 'Leer', 'Escribir', 'Compartir', etc."
    echo "5. Test other languages (French, Russian)"
else
    echo ""
    echo "❌ Some translation fixes are missing"
    echo "Please check the missing elements above"
fi

echo ""
echo "✨ Teams & RBAC translation testing completed!"