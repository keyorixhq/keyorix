#!/bin/bash

echo "🔍 Testing Overview vs Status links..."

# Check the links in the sidebar
echo "📋 Overview link:"
grep -A 3 -B 1 "onclick.*overview" web/dist/index.html

echo ""
echo "📋 Status link:"
grep -A 3 -B 1 "status.html" web/dist/index.html

echo ""
echo "🔍 Checking if both pages exist:"
if [ -f "web/dist/index.html" ]; then
    echo "✅ index.html (Overview page) exists"
else
    echo "❌ index.html missing"
fi

if [ -f "web/dist/status.html" ]; then
    echo "✅ status.html exists"
else
    echo "❌ status.html missing"
fi

echo ""
echo "🌐 Starting test server..."
cd web/dist
python3 -m http.server 8083 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8083"
echo ""
echo "📋 Test both links:"
echo "1. Overview link should show the main dashboard (stays on same page)"
echo "2. Status link should navigate to status.html (different page)"
echo ""
echo "🔗 Open http://localhost:8083 and test both sidebar links"
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID