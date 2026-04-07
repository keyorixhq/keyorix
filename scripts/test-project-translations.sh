#!/bin/bash

echo "🌐 Testing Project Content Translation Fixes..."
echo "==============================================="

# Check if main dashboard exists
if [[ ! -f "web/dist/index.html" ]]; then
    echo "❌ Main dashboard not found"
    exit 1
fi

echo "✅ Main dashboard found"

# Check if project elements have IDs
echo ""
echo "🔍 Checking project element IDs..."
project_ids=(
    "project-mobile-backend-name"
    "project-mobile-backend-desc"
    "project-mobile-frontend-name"
    "project-mobile-frontend-desc"
    "project-test-deployment-name"
    "project-test-deployment-desc"
    "project-stage-team-name"
    "project-stage-team-desc"
    "project-dev-team-name"
    "project-dev-team-desc"
    "project-standalone-app-name"
    "project-standalone-app-desc"
)

missing_project_ids=0
for id in "${project_ids[@]}"; do
    if grep -q "id=\"$id\"" web/dist/index.html; then
        echo "✅ Found project ID: $id"
    else
        echo "❌ Missing project ID: $id"
        ((missing_project_ids++))
    fi
done

# Check if team elements have IDs
echo ""
echo "🔍 Checking team element IDs..."
team_ids=(
    "team-mobile-devs-name"
    "team-mobile-devs-desc"
    "team-uat-testing-name"
    "team-uat-testing-desc"
    "team-devops-name"
    "team-devops-desc"
    "team-qa-name"
    "team-qa-desc"
    "team-infra-name"
    "team-infra-desc"
    "team-sec-name"
    "team-sec-desc"
)

missing_team_ids=0
for id in "${team_ids[@]}"; do
    if grep -q "id=\"$id\"" web/dist/index.html; then
        echo "✅ Found team ID: $id"
    else
        echo "❌ Missing team ID: $id"
        ((missing_team_ids++))
    fi
done

# Check Spanish translations
echo ""
echo "🔍 Checking Spanish translations..."
spanish_translations=(
    "Backend Móvil"
    "Servicios API para aplicaciones móviles"
    "Frontend Móvil"
    "Aplicación móvil React Native"
    "Desarrolladores Móviles"
    "Equipo de desarrollo de aplicaciones móviles"
    "Control de Calidad"
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
    "Backend Mobile"
    "Services API pour applications mobiles"
    "Frontend Mobile"
    "Application mobile React Native"
    "Développeurs Mobiles"
    "Équipe de développement d"
    "Assurance Qualité"
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
    "Мобильный Бэкенд"
    "API сервисы для мобильных приложений"
    "Мобильный Фронтенд"
    "Мобильное приложение React Native"
    "Мобильные Разработчики"
    "Команда разработки мобильных приложений"
    "Контроль Качества"
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
echo "🎯 Translation Fix Summary:"
echo "=========================="
echo "Project IDs: $((${#project_ids[@]} - missing_project_ids))/${#project_ids[@]} found"
echo "Team IDs: $((${#team_ids[@]} - missing_team_ids))/${#team_ids[@]} found"
echo "Spanish translations: $((${#spanish_translations[@]} - missing_spanish))/${#spanish_translations[@]} found"
echo "French translations: $((${#french_translations[@]} - missing_french))/${#french_translations[@]} found"
echo "Russian translations: $((${#russian_translations[@]} - missing_russian))/${#russian_translations[@]} found"

if [[ $missing_project_ids -eq 0 && $missing_team_ids -eq 0 && $missing_spanish -eq 0 && $missing_french -eq 0 && $missing_russian -eq 0 ]]; then
    echo ""
    echo "✅ All translation fixes implemented successfully!"
    echo ""
    echo "🚀 Test the fixes:"
    echo "=================="
    echo "1. Open web/dist/index.html in browser"
    echo "2. Switch to Spanish language"
    echo "3. Check Projects tab - content should be in Spanish"
    echo "4. Check Teams tab - content should be in Spanish"
    echo "5. Test other languages (French, Russian)"
else
    echo ""
    echo "❌ Some translation fixes are missing"
    echo "Please check the missing elements above"
fi

echo ""
echo "✨ Project translation testing completed!"