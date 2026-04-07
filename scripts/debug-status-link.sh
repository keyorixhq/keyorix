#!/bin/bash

echo "🔍 Debugging Status link issue..."

# Check if status.html exists
if [ -f "web/dist/status.html" ]; then
    echo "✅ status.html exists"
else
    echo "❌ status.html does not exist"
    exit 1
fi

# Check the Status link in index.html
echo "🔗 Status link in sidebar:"
grep -A 10 -B 2 'href="status.html"' web/dist/index.html

echo ""
echo "🔍 Checking for any JavaScript that might interfere..."

# Check for any preventDefault calls
echo "preventDefault calls:"
grep -n "preventDefault" web/dist/index.html || echo "None found"

echo ""
echo "🔍 Checking for event.stopPropagation calls..."
grep -n "stopPropagation" web/dist/index.html || echo "None found"

echo ""
echo "🌐 Starting test server..."
cd web/dist
python3 -m http.server 8081 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8081"
echo "📋 Test steps:"
echo "1. Open http://localhost:8081 in your browser"
echo "2. Click the 'Status' link in the left sidebar"
echo "3. It should navigate to the status page"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID