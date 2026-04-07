#!/bin/bash

echo "🌐 Testing Permission Matrix Translation Fixes..."
echo "================================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if permission matrix labels have data-translate attributes
echo ""
echo "🔍 Checking permission matrix label translations..."
matrix_labels=(
    "read-secrets-label"
    "write-secrets-label"
    "admin-access-label"
    "audit-logs-label"
    "all-teams-label"
)

missing_labels=0
for label in "${matrix_labels[@]}"; do
    if grep -q "data-translate=\"$label\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $label"
    else
        echo "❌ Missing data-translate for: $label"
        ((missing_labels++))
    fi
done

# Check if team names in matrix have data-translate attributes
echo ""
echo "🔍 Checking team name translations in matrix..."
team_matrix_labels=(
    "mobile-devs-matrix"
    "devops-matrix"
    "qa-matrix"
    "infra-matrix"
    "sec-team-matrix"
)

missing_teams=0
for team in "${team_matrix_labels[@]}"; do
    if grep -q "data-translate=\"$team\"" web/dist/index.html; then
        echo "✅ Found data-translate for: $team"
    else
        echo "❌ Missing data-translate for: $team"
        ((missing_teams++))
    fi
done

# Check Spanish translations
echo ""
echo "🔍 Checking Spanish translations..."
spanish_translations=(
    "Leer Secretos"
    "Escribir Secretos"
    "Acceso de Administrador"
    "Registros de Auditoría"
    "Todos los Equipos"
    "Desarrolladores Móviles"
    "Control de Calidad"
    "Infraestructura"
    "Equipo de Seguridad"
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
    "Lire les Secrets"
    "Écrire les Secrets"
    "Accès Administrateur"
    "Journaux d"
    "Toutes les Équipes"
    "Développeurs Mobiles"
    "Assurance Qualité"
    "Infrastructure"
    "Équipe Sécurité"
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
    "Чтение Секретов"
    "Запись Секретов"
    "Административный Доступ"
    "Журналы Аудита"
    "Все Команды"
    "Мобильные Разработчики"
    "Контроль Качества"
    "Инфраструктура"
    "Команда Безопасности"
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
echo "🎯 Permission Matrix Translation Fix Summary:"
echo "============================================="
echo "Matrix labels: $((${#matrix_labels[@]} - missing_labels))/${#matrix_labels[@]} have data-translate"
echo "Team names: $((${#team_matrix_labels[@]} - missing_teams))/${#team_matrix_labels[@]} have data-translate"
echo "Spanish translations: $((${#spanish_translations[@]} - missing_spanish))/${#spanish_translations[@]} found"
echo "French translations: $((${#french_translations[@]} - missing_french))/${#french_translations[@]} found"
echo "Russian translations: $((${#russian_translations[@]} - missing_russian))/${#russian_translations[@]} found"

if [[ $missing_labels -eq 0 && $missing_teams -eq 0 && $missing_spanish -eq 0 && $missing_french -eq 0 && $missing_russian -eq 0 ]]; then
    echo ""
    echo "✅ All permission matrix translation fixes implemented successfully!"
    echo ""
    echo "🚀 Test the fixes:"
    echo "=================="
    echo "1. Open web/dist/index.html in browser"
    echo "2. Navigate to Teams tab"
    echo "3. Switch to Spanish language"
    echo "4. Verify permission matrix content is translated:"
    echo "   - 'Read Secrets' → 'Leer Secretos'"
    echo "   - 'Write Secrets' → 'Escribir Secretos'"
    echo "   - 'Admin Access' → 'Acceso de Administrador'"
    echo "   - 'Audit Logs' → 'Registros de Auditoría'"
    echo "   - 'All Teams' → 'Todos los Equipos'"
    echo "   - Team names are translated in matrix"
    echo "5. Test other languages (French, Russian)"
else
    echo ""
    echo "❌ Some permission matrix translation fixes are missing"
    echo "Please check the missing elements above"
fi

echo ""
echo "✨ Permission matrix translation testing completed!"