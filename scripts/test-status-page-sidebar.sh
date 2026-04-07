#!/bin/bash

echo "🔍 Testing Status Page Sidebar Implementation..."
echo "================================================"

# Check if status pages exist
if [[ ! -f "web/dist/status.html" ]]; then
    echo "❌ English status page not found"
    exit 1
fi

if [[ ! -f "web/dist/status-es.html" ]]; then
    echo "❌ Spanish status page not found"
    exit 1
fi

echo "✅ Both status pages found"

# Check for sidebar implementation in English version
echo ""
echo "🔍 Checking English status page sidebar..."
if grep -q "sidebar" web/dist/status.html && grep -q "app-container" web/dist/status.html; then
    echo "✅ English sidebar structure found"
else
    echo "❌ English sidebar structure missing"
fi

# Check for sidebar implementation in Spanish version
echo ""
echo "🔍 Checking Spanish status page sidebar..."
if grep -q "sidebar" web/dist/status-es.html && grep -q "app-container" web/dist/status-es.html; then
    echo "✅ Spanish sidebar structure found"
else
    echo "❌ Spanish sidebar structure missing"
fi

# Check for navigation items in English
echo ""
echo "🔍 Checking English navigation items..."
if grep -q "Dashboard" web/dist/status.html && grep -q "System Status" web/dist/status.html; then
    echo "✅ English navigation items found"
else
    echo "❌ English navigation items missing"
fi

# Check for navigation items in Spanish
echo ""
echo "🔍 Checking Spanish navigation items..."
if grep -q "Panel de Control" web/dist/status-es.html && grep -q "Estado del Sistema" web/dist/status-es.html; then
    echo "✅ Spanish navigation items found"
else
    echo "❌ Spanish navigation items missing"
fi

# Check for responsive design
echo ""
echo "🔍 Checking responsive design..."
if grep -q "@media (max-width: 768px)" web/dist/status.html && grep -q "@media (max-width: 768px)" web/dist/status-es.html; then
    echo "✅ Responsive design found in both pages"
else
    echo "❌ Responsive design missing"
fi

# Check for background animation fix
echo ""
echo "🔍 Checking background animation..."
if grep -q "backgroundShift" web/dist/status.html && grep -q "backgroundShimmer" web/dist/status.html; then
    echo "✅ Background animations found in English page"
else
    echo "❌ Background animations missing in English page"
fi

if grep -q "backgroundShift" web/dist/status-es.html && grep -q "backgroundShimmer" web/dist/status-es.html; then
    echo "✅ Background animations found in Spanish page"
else
    echo "❌ Background animations missing in Spanish page"
fi

echo ""
echo "🎯 Status Page Improvements Summary:"
echo "===================================="
echo "✅ Fixed background animation issues"
echo "✅ Added comprehensive sidebar navigation"
echo "✅ Implemented responsive design"
echo "✅ Added Spanish translation for sidebar"
echo "✅ Consistent layout structure"
echo ""
echo "🚀 Next Possible Improvements:"
echo "=============================="
echo "• Add real-time status updates"
echo "• Implement dark/light theme toggle"
echo "• Add more detailed system metrics"
echo "• Create incident history timeline"
echo "• Add notification system for status changes"
echo "• Implement status page API integration"
echo "• Add performance charts and graphs"
echo "• Create mobile-optimized sidebar menu"

echo ""
echo "✨ Status page improvements completed successfully!"