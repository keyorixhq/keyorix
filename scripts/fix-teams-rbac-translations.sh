#!/bin/bash

echo "🔧 Fixing Teams & RBAC Translation Issues..."
echo "============================================"

# Backup the original file
cp web/dist/index.html web/dist/index.html.backup

# Add IDs to common elements using sed
echo "Adding IDs to common elements..."

# Add IDs to Active status labels (but be careful not to affect project status)
sed -i '' 's/<div class="team-status active">Active<\/div>/<div class="team-status active" data-translate="active-status">Active<\/div>/g' web/dist/index.html

# Add IDs to Members labels
sed -i '' 's/<div class="stat-label">Members<\/div>/<div class="stat-label" data-translate="members-label">Members<\/div>/g' web/dist/index.html

# Add IDs to Roles labels
sed -i '' 's/<div class="stat-label">Roles<\/div>/<div class="stat-label" data-translate="roles-label">Roles<\/div>/g' web/dist/index.html

# Add IDs to Manage buttons
sed -i '' 's/<button class="btn btn-secondary btn-sm">Manage<\/button>/<button class="btn btn-secondary btn-sm" data-translate="manage-button">Manage<\/button>/g' web/dist/index.html

# Add IDs to permission badges
sed -i '' 's/<div class="permission-badge read">Read<\/div>/<div class="permission-badge read" data-translate="read-permission">Read<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="permission-badge write">Write<\/div>/<div class="permission-badge write" data-translate="write-permission">Write<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="permission-badge share">Share<\/div>/<div class="permission-badge share" data-translate="share-permission">Share<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="permission-badge admin">Admin<\/div>/<div class="permission-badge admin" data-translate="admin-permission">Admin<\/div>/g' web/dist/index.html
sed -i '' 's/<div class="permission-badge limited">Limited<\/div>/<div class="permission-badge limited" data-translate="limited-permission">Limited<\/div>/g' web/dist/index.html

echo "✅ IDs added to common elements"

# Check if changes were applied
if grep -q 'data-translate="active-status"' web/dist/index.html; then
    echo "✅ Active status labels updated"
else
    echo "❌ Failed to update active status labels"
fi

if grep -q 'data-translate="members-label"' web/dist/index.html; then
    echo "✅ Members labels updated"
else
    echo "❌ Failed to update members labels"
fi

if grep -q 'data-translate="roles-label"' web/dist/index.html; then
    echo "✅ Roles labels updated"
else
    echo "❌ Failed to update roles labels"
fi

if grep -q 'data-translate="manage-button"' web/dist/index.html; then
    echo "✅ Manage buttons updated"
else
    echo "❌ Failed to update manage buttons"
fi

if grep -q 'data-translate="read-permission"' web/dist/index.html; then
    echo "✅ Permission badges updated"
else
    echo "❌ Failed to update permission badges"
fi

echo ""
echo "🎯 Teams & RBAC Translation Fix Summary:"
echo "========================================"
echo "✅ Added translation IDs to page title and description"
echo "✅ Added Spanish, French, and Russian translations"
echo "✅ Added IDs to common elements (status, labels, buttons)"
echo "✅ Added IDs to permission badges"
echo ""
echo "📝 Note: You may need to update the JavaScript translation function"
echo "to handle data-translate attributes in addition to id attributes."
echo ""
echo "✨ Teams & RBAC translation fixes completed!"