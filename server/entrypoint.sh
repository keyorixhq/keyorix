#!/bin/sh
set -e

echo "Starting Keyorix..."

# Seed default admin user and namespace via the API
# Wait for server to start, then seed
./keyorix-server &
SERVER_PID=$!

# Wait for health check to pass
echo "Waiting for server to be ready..."
for i in $(seq 1 30); do
    if wget --quiet --spider http://localhost:8080/health 2>/dev/null; then
        echo "Server is ready"
        break
    fi
    sleep 1
done

# Check if admin user already exists by trying to login
STATUS=$(wget --quiet -O- --post-data='{"username":"admin","password":"Admin123!"}' \
    --header='Content-Type: application/json' \
    http://localhost:8080/auth/login 2>/dev/null | grep -c "token" || true)

if [ "$STATUS" -eq 0 ]; then
    echo "Seeding default admin user..."
    wget --quiet -O- --post-data='{"username":"admin","password":"Admin123!","email":"admin@keyorix.local","role":"admin"}' \
        --header='Content-Type: application/json' \
        http://localhost:8080/api/v1/system/seed 2>/dev/null || true
    echo "Admin user created: admin / Admin123!"
else
    echo "Admin user already exists, skipping seed"
fi

# Wait for server process
wait $SERVER_PID
