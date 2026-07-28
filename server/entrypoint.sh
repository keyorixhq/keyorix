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
# and changes nothing once an admin exists. /system/init always requires a
# matching bootstrap token (operator-set via KEYORIX_BOOTSTRAP_TOKEN, or else a
# random one the server generates and only logs) — without KEYORIX_BOOTSTRAP_TOKEN
# set here, this call has no token to send and is rejected.
if [ -n "$KEYORIX_ADMIN_PASSWORD" ]; then
    ADMIN_USER="${KEYORIX_ADMIN_USERNAME:-admin}"
    ADMIN_EMAIL="${KEYORIX_ADMIN_EMAIL:-admin@keyorix.local}"
    if [ -z "$KEYORIX_BOOTSTRAP_TOKEN" ]; then
        echo "KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN is not — skipping"
        echo "auto-bootstrap (the server-generated random token can't be read back here)."
        echo "Set KEYORIX_BOOTSTRAP_TOKEN, or initialise manually: keyorix system init --server http://<host>:8080" # NOSONAR -- documentation string, not a network connection
    else
        echo "Bootstrapping admin user '$ADMIN_USER' (idempotent)..."
        # Write the POST body (which embeds the admin password) to a private temp
        # file and hand it to wget via --post-file instead of --post-data: argv is
        # visible to any process sharing this container's PID namespace via
        # `ps`/`/proc/<pid>/cmdline`, so passing the password inline as a wget flag
        # would leak it on every first boot. `mktemp -d` creates the directory with
        # 0700 permissions (only this UID can traverse it), and the payload file
        # inside it is additionally chmod'd 0600 as defense in depth. The whole
        # directory is removed as soon as the request completes (or the shell exits).
        BOOTSTRAP_TMPDIR=$(mktemp -d)
        trap 'rm -rf "$BOOTSTRAP_TMPDIR"' EXIT
        BOOTSTRAP_PAYLOAD_FILE="$BOOTSTRAP_TMPDIR/bootstrap.json"
        : > "$BOOTSTRAP_PAYLOAD_FILE"
        chmod 600 "$BOOTSTRAP_PAYLOAD_FILE"
        # Escape JSON special characters (backslash then double-quote) before
        # interpolating values into the payload — prevents malformed JSON or
        # JSON-injection if the password contains \ or " characters.
        json_escape() { local v; v="$1"; printf '%s' "$v" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
        ADMIN_USER_J=$(json_escape "$ADMIN_USER")
        ADMIN_EMAIL_J=$(json_escape "$ADMIN_EMAIL")
        ADMIN_PASS_J=$(json_escape "$KEYORIX_ADMIN_PASSWORD")
        printf '{"username":"%s","email":"%s","password":"%s","display_name":"Administrator"}' \
            "$ADMIN_USER_J" "$ADMIN_EMAIL_J" "$ADMIN_PASS_J" > "$BOOTSTRAP_PAYLOAD_FILE"
        wget --quiet -O- \
            --header='Content-Type: application/json' \
            --header="X-Keyorix-Bootstrap-Token: $KEYORIX_BOOTSTRAP_TOKEN" \
            --post-file="$BOOTSTRAP_PAYLOAD_FILE" \
            http://localhost:8080/system/init 2>/dev/null || \
            echo "Bootstrap call failed (server may already be initialised) — continuing."
        rm -rf "$BOOTSTRAP_TMPDIR"
        trap - EXIT
    fi
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: keyorix system init --server http://<host>:8080" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
