#!/bin/bash

echo "🤖 Testing AI Assistant link..."

# Start server
cd web/dist
python3 -m http.server 8083 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8083"
echo ""
echo "🤖 AI Assistant link has been added to the bottom of the sidebar"
echo "📋 Test steps:"
echo "1. Open http://localhost:8083 in your browser"
echo "2. Look for the 'AI Assistant' link at the bottom of the left sidebar"
echo "3. Click the 'AI Assistant' link"
echo "4. A modal should appear showing AI Assistant features"
echo ""
echo "Features shown in the modal:"
echo "• 🔐 Secret Analysis"
echo "• 🛡️ Security Insights" 
echo "• ⚡ Workflow Optimization"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID