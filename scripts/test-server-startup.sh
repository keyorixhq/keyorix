#!/bin/bash

echo "🧪 Testing Keyorix Server Startup"
echo "================================="

# Kill any existing servers
echo "🔄 Stopping any existing servers..."
pkill keyorix-server 2>/dev/null || true
sleep 2

# Build the server
echo "🔨 Building server..."
go build -o keyorix-server ./server/main.go

# Check if config exists
if [[ ! -f "keyorix.yaml" ]]; then
    echo "📝 Creating keyorix.yaml config..."
    cat > keyorix.yaml << 'EOF'
locale:
  language: "en"
  fallback_language: "en"

server:
  http:
    port: 8080
    host: "localhost"
  grpc:
    port: 9090
    host: "localhost"

storage:
  type: "local"
  database:
    path: "./keyorix.db"
  encryption:
    enabled: false

secrets:
  max_size_mb: 10
  chunk_size_kb: 64

telemetry:
  enabled: false

security:
  check_file_permissions: false

soft_delete:
  enabled: true
  retention_days: 30

purge:
  enabled: false
  schedule: "0 2 * * *"
EOF
fi

# Start server
echo "🚀 Starting server..."
./keyorix-server --config keyorix.yaml > server-test.log 2>&1 &
SERVER_PID=$!

# Wait for server to start
echo "⏳ Waiting for server to start..."
for i in {1..10}; do
    if curl -s http://localhost:8080/health > /dev/null 2>&1; then
        echo "✅ Server is running!"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "❌ Server failed to start. Checking logs..."
        cat server-test.log
        kill $SERVER_PID 2>/dev/null || true
        exit 1
    fi
    sleep 1
done

# Test the server
echo "🧪 Testing server endpoints..."

# Health check
echo "Testing health endpoint..."
HEALTH_RESPONSE=$(curl -s http://localhost:8080/health)
if [[ -n "$HEALTH_RESPONSE" ]]; then
    echo "✅ Health endpoint working: $HEALTH_RESPONSE"
else
    echo "❌ Health endpoint not responding"
fi

# Test CLI
echo "🔧 Testing CLI..."
./keyorix status

echo "🎉 Server test complete!"
echo "Server PID: $SERVER_PID"
echo "To stop server: kill $SERVER_PID"