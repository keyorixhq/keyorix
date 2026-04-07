#!/bin/bash

echo "🤖 Testing AI Assistant right-side panel..."

# Start server
cd web/dist
python3 -m http.server 8085 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8085"
echo ""
echo "🤖 AI Assistant has been recreated as a right-side panel"
echo "📋 Test steps:"
echo "1. Open http://localhost:8085 in your browser"
echo "2. Click the 'AI Assistant' link in the left sidebar"
echo "3. A right-side panel should slide in from the right"
echo "4. The left sidebar remains visible and functional"
echo "5. Click the X button or press Escape to close the panel"
echo ""
echo "Features in the right-side panel:"
echo "• 🔐 Secret Analysis capability card"
echo "• 🛡️ Security Insights capability card"
echo "• ⚡ Workflow Optimization capability card"
echo "• 🤖 Natural Language capability card"
echo "• Sample chat interface with preview messages"
echo "• Disabled input area (coming soon)"
echo "• Smooth slide-in/out animation"
echo "• Escape key to close"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID