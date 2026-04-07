#!/bin/bash

echo "🔧 Creating Translation Test Page..."
echo "==================================="

# Create a simple test page to verify translations are working
cat > web/dist/translation-test.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Translation Test - Keyorix</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background: #0a0a0a;
            color: #ffffff;
        }
        .test-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #333;
            border-radius: 8px;
            background: #111;
        }
        .test-item {
            margin: 10px 0;
            padding: 8px;
            background: #222;
            border-radius: 4px;
        }
        .language-buttons {
            margin: 20px 0;
        }
        button {
            margin: 5px;
            padding: 10px 15px;
            background: #0070f3;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        button:hover {
            background: #0056b3;
        }
        .status {
            color: #10b981;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>🌐 Keyorix Translation Test</h1>
    
    <div class="language-buttons">
        <button onclick="testTranslation('en')">English</button>
        <button onclick="testTranslation('es')">Español</button>
        <button onclick="testTranslation('fr')">Français</button>
        <button onclick="testTranslation('ru')">Русский</button>
    </div>

    <div class="test-section">
        <h2>Page Titles</h2>
        <div class="test-item">Overview: <span id="page-title">Overview</span></div>
        <div class="test-item">Projects: <span id="projects-page-title">Projects</span></div>
        <div class="test-item">Teams & RBAC: <span id="teams-rbac-title">Teams & RBAC</span></div>
    </div>

    <div class="test-section">
        <h2>RBAC Labels</h2>
        <div class="test-item">Total Users: <span data-translate="total-users-label">Total Users</span></div>
        <div class="test-item">Active Teams: <span data-translate="active-teams-label">Active Teams</span></div>
        <div class="test-item">Total Roles: <span data-translate="total-roles-label">Total Roles</span></div>
        <div class="test-item">Permissions: <span data-translate="permissions-label">Permissions</span></div>
    </div>

    <div class="test-section">
        <h2>System Status</h2>
        <div class="test-item">Status: <span id="system-status" class="status">All systems operational</span></div>
    </div>

    <div class="test-section">
        <h2>Project Labels</h2>
        <div class="test-item">Secrets: <span data-translate="secrets-label">Secrets</span></div>
        <div class="test-item">Days Rotation: <span data-translate="days-rotation-label">Days Rotation</span></div>
        <div class="test-item">Environments: <span data-translate="environments-label">Environments</span></div>
    </div>

    <div id="test-result" class="test-section" style="display: none;">
        <h2>Test Result</h2>
        <div id="result-content"></div>
    </div>

    <script>
        // Copy the translations from the main dashboard
        const translations = {
            en: {
                'page-title': 'Overview',
                'projects-page-title': 'Projects',
                'teams-rbac-title': 'Teams & RBAC',
                'system-status': 'All systems operational',
                'total-users-label': 'Total Users',
                'active-teams-label': 'Active Teams',
                'total-roles-label': 'Total Roles',
                'permissions-label': 'Permissions',
                'secrets-label': 'Secrets',
                'days-rotation-label': 'Days Rotation',
                'environments-label': 'Environments'
            },
            es: {
                'page-title': 'Resumen',
                'projects-page-title': 'Proyectos',
                'teams-rbac-title': 'Equipos y RBAC',
                'system-status': 'Todos los sistemas operativos',
                'total-users-label': 'Usuarios Totales',
                'active-teams-label': 'Equipos Activos',
                'total-roles-label': 'Roles Totales',
                'permissions-label': 'Permisos',
                'secrets-label': 'Secretos',
                'days-rotation-label': 'Días de Rotación',
                'environments-label': 'Entornos'
            },
            fr: {
                'page-title': 'Aperçu',
                'projects-page-title': 'Projets',
                'teams-rbac-title': 'Équipes et RBAC',
                'system-status': 'Tous les systèmes opérationnels',
                'total-users-label': 'Utilisateurs Totaux',
                'active-teams-label': 'Équipes Actives',
                'total-roles-label': 'Rôles Totaux',
                'permissions-label': 'Permissions',
                'secrets-label': 'Secrets',
                'days-rotation-label': 'Jours de Rotation',
                'environments-label': 'Environnements'
            },
            ru: {
                'page-title': 'Обзор',
                'projects-page-title': 'Проекты',
                'teams-rbac-title': 'Команды и RBAC',
                'system-status': 'Все системы работают',
                'total-users-label': 'Всего Пользователей',
                'active-teams-label': 'Активные Команды',
                'total-roles-label': 'Всего Ролей',
                'permissions-label': 'Разрешения',
                'secrets-label': 'Секреты',
                'days-rotation-label': 'Дни Ротации',
                'environments-label': 'Среды'
            }
        };

        function applyTranslations(lang) {
            const t = translations[lang] || translations.en;
            let translatedCount = 0;
            let totalCount = 0;

            // Update elements by ID
            Object.keys(t).forEach(key => {
                const element = document.getElementById(key);
                if (element) {
                    element.textContent = t[key];
                    translatedCount++;
                }
                totalCount++;
            });

            // Update elements with data-translate attributes
            Object.keys(t).forEach(key => {
                const elements = document.querySelectorAll(`[data-translate="${key}"]`);
                elements.forEach(element => {
                    element.textContent = t[key];
                });
            });

            return { translatedCount, totalCount };
        }

        function testTranslation(lang) {
            const result = applyTranslations(lang);
            const resultDiv = document.getElementById('test-result');
            const contentDiv = document.getElementById('result-content');
            
            const langNames = {
                en: 'English',
                es: 'Spanish',
                fr: 'French',
                ru: 'Russian'
            };

            contentDiv.innerHTML = `
                <div class="status">✅ Applied ${langNames[lang]} translations</div>
                <div>Translated ${result.translatedCount}/${result.totalCount} elements</div>
                <div>Language code: ${lang}</div>
                <div>Timestamp: ${new Date().toLocaleTimeString()}</div>
            `;
            
            resultDiv.style.display = 'block';
            
            // Update page title
            document.title = `Translation Test - ${langNames[lang]} - Keyorix`;
        }

        // Initialize with English
        testTranslation('en');
    </script>
</body>
</html>
EOF

echo "✅ Translation test page created: web/dist/translation-test.html"
echo ""
echo "🚀 How to use the test page:"
echo "============================"
echo "1. Open web/dist/translation-test.html in your browser"
echo "2. Click the language buttons to test translations"
echo "3. Verify that all text changes to the selected language"
echo "4. If translations work here but not in main dashboard:"
echo "   - Clear browser cache for the main dashboard"
echo "   - Hard refresh the main dashboard (Ctrl+F5)"
echo "   - Check browser console for JavaScript errors"
echo ""
echo "🔍 If translations don't work in test page:"
echo "==========================================="
echo "1. Check browser console for errors"
echo "2. Verify JavaScript is enabled"
echo "3. Try a different browser"
echo ""
echo "✨ Translation test page ready!"