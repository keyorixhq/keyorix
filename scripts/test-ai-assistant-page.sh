#!/bin/bash

echo "🤖 Testing AI Assistant page..."

# Start server
cd web/dist
python3 -m http.server 8084 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8084"
echo ""
echo "🤖 AI Assistant page has been created with full sidebar navigation"
echo "📋 Test steps:"
echo "1. Open http://localhost:8084 in your browser"
echo "2. Click the 'AI Assistant' link in the left sidebar"
echo "3. You should navigate to the dedicated AI Assistant page"
echo "4. The sidebar should remain visible on the AI Assistant page"
echo "5. You can navigate back to other pages using the sidebar"
echo ""
echo "Features on the AI Assistant page:"
echo "• 🔐 Secret Analysis"
echo "• 🛡️ Security Insights" 
echo "• ⚡ Workflow Optimization"
echo "• 📊 Smart Analytics"
echo "• 🤖 Natural Language Interface"
echo "• 🎯 Predictive Recommendations"
echo "• Chat interface preview (disabled/coming soon)"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID