#!/bin/bash

echo "🌐 Testing Remaining Projects Page Translation Fixes..."
echo "======================================================"

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if summary labels have data-translate attributes
echo ""
echo "🔍 Checking summary label translations..."
summary_labels=(
    "total-projects-label"
    "total-secrets-summary"
    "avg-rotation-days-label"
    "total-environments-label"
)

missing_summary=0
for label in "${summary_labels[@]}"; do
    if grep -q "data-translate=\"$label\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $label"
    else
        echo "❌ Missing data-translate for: $label"
        ((missing_summary++))
    fi
done

# Check if project stat labels have data-translate attributes
echo ""
echo "🔍 Checking project stat label translations..."
stat_labels=(
    "secrets-label"
    "days-rotation-label"
    "environments-label"
)

missing_stats=0
for label in "${stat_labels[@]}"; do
    if grep -q "data-translate=\"$label\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $label"
    else
        echo "❌ Missing data-translate for: $label"
        ((missing_stats++))
    fi
done

# Check if additional rotation policies have data-translate attributes
echo ""
echo "🔍 Checking additional rotation policy translations..."
rotation_labels=(
    "auto-rotation-30-days"
    "auto-rotation-60-days"
)

missing_rotation=0
for label in "${rotation_labels[@]}"; do
    if grep -q "data-translate=\"$label\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $label"
    else
        echo "❌ Missing data-translate for: $label"
        ((missing_rotation++))
    fi
done

# Check Spanish translations
echo ""
echo "🔍 Checking Spanish translations..."
spanish_translations=(
    "Proyectos Totales"
    "Secretos Totales"
    "Días de Rotación Promedio"
    "Entornos Totales"
    "Secretos"
    "Días de Rotación"
    "Entornos"
    "Auto-rotación cada 30 días"
    "Auto-rotación cada 60 días"
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
    "Projets Totaux"
    "Secrets Totaux"
    "Jours de Rotation Moyens"
    "Environnements Totaux"
    "Secrets"
    "Jours de Rotation"
    "Environnements"
    "Auto-rotation tous les 30 jours"
    "Auto-rotation tous les 60 jours"
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
    "Всего Проектов"
    "Всего Секретов"
    "Средние Дни Ротации"
    "Всего Сред"
    "Секреты"
    "Дни Ротации"
    "Среды"
    "Авто-ротация каждые 30 дней"
    "Авто-ротация каждые 60 дней"
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

echo ""
echo "🎯 Remaining Projects Translation Fix Summary:"
echo "=============================================="
echo "Summary labels: $((${#summary_labels[@]} - missing_summary))/${#summary_labels[@]} have data-translate"
echo "Project stat labels: $((${#stat_labels[@]} - missing_stats))/${#stat_labels[@]} have data-translate"
echo "Rotation policies: $((${#rotation_labels[@]} - missing_rotation))/${#rotation_labels[@]} have data-translate"
echo "Spanish translations: $((${#spanish_translations[@]} - missing_spanish))/${#spanish_translations[@]} found"
echo "French translations: $((${#french_translations[@]} - missing_french))/${#french_translations[@]} found"
echo "Russian translations: $((${#russian_translations[@]} - missing_russian))/${#russian_translations[@]} found"

if [[ $missing_summary -eq 0 && $missing_stats -eq 0 && $missing_rotation -eq 0 && $missing_spanish -eq 0 && $missing_french -eq 0 && $missing_russian -eq 0 ]]; then
    echo ""
    echo "✅ All remaining Projects page translation fixes implemented successfully!"
    echo ""
    echo "🚀 Test the fixes:"
    echo "=================="
    echo "1. Open web/dist/index.html in browser"
    echo "2. Navigate to Projects tab"
    echo "3. Switch to Spanish language"
    echo "4. Verify ALL content is now translated:"
    echo "   - Page title: 'Proyectos'"
    echo "   - Summary statistics: 'Proyectos Totales', 'Secretos Totales', etc."
    echo "   - Project stat labels: 'Secretos', 'Días de Rotación', 'Entornos'"
    echo "   - All rotation policies are in Spanish"
    echo "5. Test other languages (French, Russian)"
else
    echo ""
    echo "❌ Some remaining Projects page translation fixes are missing"
    echo "Please check the missing elements above"
fi

echo ""
echo "✨ Remaining Projects page translation testing completed!"