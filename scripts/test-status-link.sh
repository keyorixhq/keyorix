#!/bin/bash

echo "Testing Status link navigation..."

# Start a simple HTTP server
cd web/dist
python3 -m http.server 8080 &
SERVER_PID=$!

# Wait for server to start
sleep 2

echo "Server started at http://localhost:8080"
echo "Testing Status link..."

# Test if status.html is accessible
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/status.html

if [ $? -eq 0 ]; then
    echo "✅ status.html is accessible"
    echo "🌐 Open http://localhost:8080 in your browser"
    echo "🔗 Click the Status link in the sidebar to test"
    echo ""
    echo "Press Ctrl+C to stop the server"
    wait $SERVER_PID
else
    echo "❌ status.html is not accessible"
    kill $SERVER_PID
fi