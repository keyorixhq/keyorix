#!/bin/bash

echo "🔧 Fixing Permission Matrix Translation Issues..."
echo "================================================"

# Backup the original file
cp web/dist/index.html web/dist/index.html.backup2

# Add data-translate attributes to team names in matrix badges
echo "Adding data-translate attributes to team names in permission matrix..."

# Replace team names in matrix badges with data-translate attributes
sed -i '' 's/<span class="matrix-badge granted">Mobile Devs<\/span>/<span class="matrix-badge granted" data-translate="mobile-devs-matrix">Mobile Devs<\/span>/g' web/dist/index.html
sed -i '' 's/<span class="matrix-badge granted">DevOps<\/span>/<span class="matrix-badge granted" data-translate="devops-matrix">DevOps<\/span>/g' web/dist/index.html
sed -i '' 's/<span class="matrix-badge granted">Q&A<\/span>/<span class="matrix-badge granted" data-translate="qa-matrix">Q&A<\/span>/g' web/dist/index.html
sed -i '' 's/<span class="matrix-badge granted">Infra<\/span>/<span class="matrix-badge granted" data-translate="infra-matrix">Infra<\/span>/g' web/dist/index.html
sed -i '' 's/<span class="matrix-badge granted">Sec Team<\/span>/<span class="matrix-badge granted" data-translate="sec-team-matrix">Sec Team<\/span>/g' web/dist/index.html

echo "✅ Data-translate attributes added to permission matrix elements"

# Check if changes were applied
if grep -q 'data-translate="read-secrets-label"' web/dist/index.html; then
    echo "✅ Permission matrix labels updated"
else
    echo "❌ Failed to update permission matrix labels"
fi

if grep -q 'data-translate="mobile-devs-matrix"' web/dist/index.html; then
    echo "✅ Team names in matrix updated"
else
    echo "❌ Failed to update team names in matrix"
fi

echo ""
echo "🎯 Permission Matrix Translation Fix Summary:"
echo "============================================="
echo "✅ Added data-translate attributes to permission labels"
echo "✅ Added data-translate attributes to team names in matrix"
echo ""
echo "📝 Next: Add translations to the translation objects"
echo ""
echo "✨ Permission matrix translation fixes completed!"