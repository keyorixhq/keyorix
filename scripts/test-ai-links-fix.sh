#!/bin/bash

echo "🔧 Testing AI links fix..."

# Start server
cd web/dist
python3 -m http.server 8088 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8088"
echo ""
echo "🔗 AI links have been fixed with explicit navigation"
echo "📋 Test steps:"
echo "1. Open http://localhost:8088 in your browser"
echo "2. Look at the AI section in the left sidebar"
echo "3. Click 'Security Insights' - should navigate to ai-security-insights.html"
echo "4. Click 'Secrets Analysis' - should navigate to ai-secrets-analysis.html"
echo "5. Both links now have explicit JavaScript navigation handlers"
echo ""
echo "The fix adds onclick handlers that force navigation:"
echo "• Security Insights: onclick=\"window.location.href='ai-security-insights.html'\""
echo "• Secrets Analysis: onclick=\"window.location.href='ai-secrets-analysis.html'\""
echo ""
echo "This ensures the links work regardless of any potential interference"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID