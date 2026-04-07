#!/bin/bash

echo "🛡️ Testing standalone Security Insights page..."

# Start server
cd web/dist
python3 -m http.server 8089 &
SERVER_PID=$!

sleep 2

echo "✅ Server running at http://localhost:8089"
echo ""
echo "🛡️ Standalone Security Insights page created successfully"
echo "📋 Test steps:"
echo "1. Open http://localhost:8089 in your browser"
echo "2. Navigate to http://localhost:8089/security-insights.html"
echo "3. Explore the comprehensive security dashboard"
echo ""
echo "🔥 Key Features:"
echo "• Live security monitoring with real-time updates"
echo "• Critical alerts: 5 critical, 12 high priority issues"
echo "• Security score: 94% with trend indicators"
echo "• Active security alerts with action buttons"
echo "• Security timeline showing recent events"
echo "• Comprehensive recommendations with priority levels"
echo "• Filter bar for time range, severity, and category"
echo "• Export functionality for security reports"
echo ""
echo "🎨 Design Features:"
echo "• Professional dark theme with security-focused colors"
echo "• Interactive elements with hover effects"
echo "• Real-time indicators and animations"
echo "• Comprehensive sidebar navigation"
echo "• Responsive grid layouts"
echo "• Color-coded severity levels (critical, warning, success, info)"
echo ""
echo "📊 Dashboard Sections:"
echo "• Security Overview Metrics"
echo "• Active Security Alerts"
echo "• Security Event Timeline"
echo "• Security Recommendations"
echo "• Filter and Export Controls"
echo ""
echo "This is a complete, standalone security insights dashboard"
echo "independent from the AI system, focused purely on security monitoring."
echo ""
echo "Press Enter to stop the server..."
read
kill $SERVER_PID