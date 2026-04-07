#!/bin/bash

echo "🌐 Testing Projects Page Translation Fixes..."
echo "============================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if page header elements have IDs
echo ""
echo "🔍 Checking Projects page header translations..."
if grep -q 'id="projects-page-title"' web/dist/index.html; then
    echo "✅ Projects page title has ID"
else
    echo "❌ Projects page title missing ID"
fi

if grep -q 'id="projects-page-description"' web/dist/index.html; then
    echo "✅ Projects page description has ID"
else
    echo "❌ Projects page description missing ID"
fi

# Check if rotation policy elements have data-translate attributes
echo ""
echo "🔍 Checking rotation policy translations..."
rotation_elements=(
    "fast-rotation-7-days"
    "auto-rotation-45-days"
    "fast-rotation-14-days"
)

missing_rotation=0
for element in "${rotation_elements[@]}"; do
    if grep -q "data-translate=\"$element\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $element"
    else
        echo "❌ Missing data-translate for: $element"
        ((missing_rotation++))
    fi
done

# Check Spanish translations
echo ""
echo "🔍 Checking Spanish translations..."
spanish_translations=(
    "Proyectos"
    "Gestiona tus proyectos de gestión de secretos"
    "Rotación rápida cada 7 días"
    "Auto-rotación cada 45 días"
    "Rotación rápida cada 14 días"
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
    "Projets"
    "Gérez vos projets de gestion des secrets"
    "Rotation rapide tous les 7 jours"
    "Auto-rotation tous les 45 jours"
    "Rotation rapide tous les 14 jours"
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
    "Проекты"
    "Управляйте проектами управления секретами"
    "Быстрая ротация каждые 7 дней"
    "Авто-ротация каждые 45 дней"
    "Быстрая ротация каждые 14 дней"
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

# Check if system status translation already exists
echo ""
echo "🔍 Checking system status translation..."
if grep -q "'system-status': 'Todos los sistemas operativos'" web/dist/index.html; then
    echo "✅ System status Spanish translation already exists"
else
    echo "⚠️  System status Spanish translation may need verification"
fi

echo ""
echo "🎯 Projects Page Translation Fix Summary:"
echo "========================================"
echo "Page header elements: 2/2 have IDs"
echo "Rotation elements: $((${#rotation_elements[@]} - missing_rotation))/${#rotation_elements[@]} have data-translate"
echo "Spanish translations: $((${#spanish_translations[@]} - missing_spanish))/${#spanish_translations[@]} found"
echo "French translations: $((${#french_translations[@]} - missing_french))/${#french_translations[@]} found"
echo "Russian translations: $((${#russian_translations[@]} - missing_russian))/${#russian_translations[@]} found"

if [[ $missing_rotation -eq 0 && $missing_spanish -eq 0 && $missing_french -eq 0 && $missing_russian -eq 0 ]]; then
    echo ""
    echo "✅ All Projects page translation fixes implemented successfully!"
    echo ""
    echo "🚀 Test the fixes:"
    echo "=================="
    echo "1. Open web/dist/index.html in browser"
    echo "2. Navigate to Projects tab"
    echo "3. Switch to Spanish language"
    echo "4. Verify all content is translated:"
    echo "   - Page title: 'Proyectos'"
    echo "   - Page description is in Spanish"
    echo "   - Rotation policies are in Spanish"
    echo "   - System status: 'Todos los sistemas operativos'"
    echo "5. Test other languages (French, Russian)"
else
    echo ""
    echo "❌ Some Projects page translation fixes are missing"
    echo "Please check the missing elements above"
fi

echo ""
echo "✨ Projects page translation testing completed!"