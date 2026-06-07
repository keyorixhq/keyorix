#!/bin/sh
set -e

echo "Starting Keyorix server..."

# Run the server in the background so we can perform an optional first-boot admin
# bootstrap once it is healthy, then hand the process the foreground.
./keyorix-server &
SERVER_PID=$!

# Always re-foreground the server on exit so signals propagate to it.
trap 'kill -TERM "$SERVER_PID" 2>/dev/null' TERM INT

echo "Waiting for server to be ready..."
for _ in $(seq 1 30); do
    if wget --quiet --spider http://localhost:8080/health 2>/dev/null; then
        echo "Server is ready"
        break
    fi
    sleep 1
done

# First-boot admin bootstrap (optional, idempotent). Only runs when an admin
# password is supplied via the environment — there are NO hardcoded credentials.
# POST /system/init is safe to call repeatedly: it reports already_initialized
# and changes nothing once an admin exists.
if [ -n "$KEYORIX_ADMIN_PASSWORD" ]; then
    ADMIN_USER="${KEYORIX_ADMIN_USERNAME:-admin}"
    ADMIN_EMAIL="${KEYORIX_ADMIN_EMAIL:-admin@keyorix.local}"
    echo "Bootstrapping admin user '$ADMIN_USER' (idempotent)..."
    wget --quiet -O- \
        --header='Content-Type: application/json' \
        --post-data="{\"username\":\"$ADMIN_USER\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$KEYORIX_ADMIN_PASSWORD\",\"display_name\":\"Administrator\"}" \
        http://localhost:8080/system/init 2>/dev/null || \
        echo "Bootstrap call failed (server may already be initialised) — continuing."
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: keyorix system init --server http://<host>:8080"
fi

# Hand the server the foreground.
wait "$SERVER_PID"
