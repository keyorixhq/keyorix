#!/bin/bash

echo "🔧 Fixing Remaining Projects Page Translation Issues..."
echo "====================================================="

# Backup the original file
cp web/dist/index.html web/dist/index.html.backup3

# Add data-translate attributes to summary labels
echo "Adding data-translate attributes to summary labels..."
sed -i '' 's/<div class="summary-label">Total Projects<\/div>/<div class="summary-label" data-translate="total-projects-label">Total Projects<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="summary-label">Total Secrets<\/div>/<div class="summary-label" data-translate="total-secrets-summary">Total Secrets<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="summary-label">Avg Rotation Days<\/div>/<div class="summary-label" data-translate="avg-rotation-days-label">Avg Rotation Days<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="summary-label">Total Environments<\/div>/<div class="summary-label" data-translate="total-environments-label">Total Environments<\/div>/g' web/dist/index.html

# Add data-translate attributes to individual project stat labels
echo "Adding data-translate attributes to project stat labels..."
sed -i '' 's/<div class="stat-label">Secrets<\/div>/<div class="stat-label" data-translate="secrets-label">Secrets<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="stat-label">Days Rotation<\/div>/<div class="stat-label" data-translate="days-rotation-label">Days Rotation<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="stat-label">Environments<\/div>/<div class="stat-label" data-translate="environments-label">Environments<\/div>/g' web/dist/index.html

# Add data-translate attributes to additional rotation policies
echo "Adding data-translate attributes to additional rotation policies..."
sed -i '' 's/<span>Auto-rotation every 30 days<\/span>/<span data-translate="auto-rotation-30-days">Auto-rotation every 30 days<\/span>/g' web/dist/index.html
sed -i '' 's/<span>Auto-rotation every 60 days<\/span>/<span data-translate="auto-rotation-60-days">Auto-rotation every 60 days<\/span>/g' web/dist/index.html

echo "✅ Data-translate attributes added to remaining elements"

# Check if changes were applied
if grep -q 'data-translate="total-projects-label"' web/dist/index.html; then
    echo "✅ Summary labels updated"
else
    echo "❌ Failed to update summary labels"
fi

if grep -q 'data-translate="secrets-label"' web/dist/index.html; then
    echo "✅ Project stat labels updated"
else
    echo "❌ Failed to update project stat labels"
fi

if grep -q 'data-translate="auto-rotation-30-days"' web/dist/index.html; then
    echo "✅ Additional rotation policies updated"
else
    echo "❌ Failed to update additional rotation policies"
fi

echo ""
echo "🎯 Remaining Projects Translation Fix Summary:"
echo "=============================================="
echo "✅ Added data-translate attributes to summary labels"
echo "✅ Added data-translate attributes to project stat labels"
echo "✅ Added data-translate attributes to additional rotation policies"
echo ""
echo "📝 Next: Add translations to the translation objects"
echo ""
echo "✨ Remaining projects translation fixes completed!"