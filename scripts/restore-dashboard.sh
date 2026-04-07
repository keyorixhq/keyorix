#!/bin/bash

# Keyorix Dashboard Restoration Script
# This script restores the main dashboard from backup if it gets corrupted

echo "🔧 Keyorix Dashboard Restoration"
echo "================================"

# Check if server is running
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo "❌ Server is not running. Please start the server first."
    exit 1
fi

# Backup current dashboard
echo "📦 Creating backup of current dashboard..."
cp web/dist/index.html web/dist/index.html.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true

# Restore from modern dashboard backup
echo "🔄 Restoring dashboard from backup..."
cp web/dist/modern-dashboard.html web/dist/index.html

# Test the restoration
echo "🧪 Testing dashboard..."
if curl -s http://localhost:8080/ | grep -q "Keyorix - Modern Secret Management"; then
    echo "✅ Dashboard restored successfully!"
    echo "🌐 Access your dashboard at: http://localhost:8080"
else
    echo "❌ Dashboard restoration failed"
    exit 1
fi

echo ""
echo "Dashboard restoration completed!"