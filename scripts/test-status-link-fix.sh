#!/bin/bash

echo "🔧 Testing Status link fix..."

# Start server
cd web/dist
python3 -m http.server 8082 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8082"
echo ""
echo "🔗 Status link has been fixed with explicit navigation"
echo "📋 Test steps:"
echo "1. Open http://localhost:8082 in your browser"
echo "2. Click the 'Status' link in the left sidebar"
echo "3. It should now navigate to the status page"
echo ""
echo "The fix adds explicit JavaScript navigation to ensure the link works"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID