#!/bin/bash

echo "🤖 Testing AI mockup pages..."

# Start server
cd web/dist
python3 -m http.server 8087 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8087"
echo ""
echo "🤖 AI Security Insights and Secrets Analysis mockup pages created"
echo "📋 Test steps:"
echo "1. Open http://localhost:8087 in your browser"
echo "2. Check the AI section in the left sidebar - now has 3 items:"
echo "   • AI Assistant (opens right panel)"
echo "   • Security Insights (dedicated page)"
echo "   • Secrets Analysis (dedicated page)"
echo "3. Navigate to each AI page and verify functionality"
echo ""
echo "🛡️ AI Security Insights page features:"
echo "• Security overview with stats (3 critical, 7 warnings, 12 recommendations)"
echo "• Interactive insight cards with severity levels"
echo "• Critical issues: weak passwords, expired certificates"
echo "• Warning issues: overdue rotations, excessive permissions"
echo "• AI recommendations for security improvements"
echo "• Action buttons for each insight"
echo ""
echo "🔍 AI Secrets Analysis page features:"
echo "• Usage patterns chart placeholder"
echo "• Key metrics: 47 secrets, 92% health score"
echo "• Analysis cards with progress bars"
echo "• Secret health list with status indicators"
echo "• Detailed analysis of rotation, access patterns, strength"
echo "• Export and refresh functionality"
echo ""
echo "Both pages maintain:"
echo "• Consistent sidebar navigation"
echo "• Professional dark theme design"
echo "• Interactive elements and hover effects"
echo "• Realistic mockup data and scenarios"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID