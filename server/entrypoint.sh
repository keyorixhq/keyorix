#!/bin/sh
set -e

echo "Starting Keyorix server..."

# Run the server in the background so we can perform an optional first-boot admin
# bootstrap once it is healthy, then hand the process the foreground.
./keyorix-server &
SERVER_PID=$!

# Always re-foreground the server on exit so signals propagate to it.
trap 'kill -TERM "$SERVER_PID" 2>/dev/null' TERM INT

# Wait for REAL readiness (GET /health answering 2xx), not a fixed number of
# tries: a first boot runs DB migrations and key setup, which on a cold Postgres
# can take well over 30 s. Bounded by KEYORIX_READY_TIMEOUT seconds (default 180),
# logs progress every 10 s, and stops early if the server process dies.
# 127.0.0.1, not localhost: busybox resolves localhost to ::1 first.
READY_TIMEOUT="${KEYORIX_READY_TIMEOUT:-180}"
echo "Waiting for server to be ready (up to ${READY_TIMEOUT}s)..."
SERVER_READY=0
waited=0
while [ "$waited" -lt "$READY_TIMEOUT" ]; do
    if wget --quiet --spider http://127.0.0.1:8080/health 2>/dev/null; then
        SERVER_READY=1
        echo "Server is ready after ${waited}s"
        break
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        echo "ERROR: keyorix-server exited before becoming ready" >&2
        wait "$SERVER_PID" || exit $?
        exit 1
    fi
    sleep 1
    waited=$((waited + 1))
    if [ $((waited % 10)) -eq 0 ]; then
        echo "Still waiting for server to be ready (${waited}s/${READY_TIMEOUT}s)..."
    fi
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
        # Fail loudly: an admin password was requested but cannot be applied, and a
        # container that reports healthy with no usable login is worse than a crash.
        echo "ERROR: KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN is not, so the" >&2
        echo "ERROR: admin cannot be bootstrapped (the server-generated random token can't be read back here)." >&2
        echo "ERROR: Set KEYORIX_BOOTSTRAP_TOKEN, or unset KEYORIX_ADMIN_PASSWORD and run \`keyorix system init\` manually." >&2
        kill -TERM "$SERVER_PID" 2>/dev/null
        wait "$SERVER_PID" 2>/dev/null
        exit 1
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
        # Bounded, logged retry. /system/init is idempotent (already_initialized
        # is a 200), so retrying is safe. If it still cannot complete, stop the
        # server and exit non-zero: never "healthy but unusable" (#3025).
        BOOTSTRAP_ATTEMPTS="${KEYORIX_BOOTSTRAP_ATTEMPTS:-10}"
        BOOTSTRAP_OK=0
        attempt=1
        while [ "$attempt" -le "$BOOTSTRAP_ATTEMPTS" ]; do
            if wget --quiet -O- \
                --header='Content-Type: application/json' \
                --header="X-Keyorix-Bootstrap-Token: $KEYORIX_BOOTSTRAP_TOKEN" \
                --post-file="$BOOTSTRAP_PAYLOAD_FILE" \
                http://127.0.0.1:8080/system/init >/dev/null 2>&1; then
                BOOTSTRAP_OK=1
                break
            fi
            echo "Bootstrap attempt ${attempt}/${BOOTSTRAP_ATTEMPTS} failed; retrying in 3s..."
            attempt=$((attempt + 1))
            sleep 3
        done
        if [ "$BOOTSTRAP_OK" -ne 1 ]; then
            rm -rf "$BOOTSTRAP_TMPDIR"
            echo "ERROR: admin bootstrap did not complete after ${BOOTSTRAP_ATTEMPTS} attempts" >&2
            echo "ERROR: (server ready=${SERVER_READY}). Check KEYORIX_BOOTSTRAP_TOKEN matches and the server logs above." >&2
            kill -TERM "$SERVER_PID" 2>/dev/null
            wait "$SERVER_PID" 2>/dev/null
            exit 1
        fi
        echo "Admin bootstrap complete."
        rm -rf "$BOOTSTRAP_TMPDIR"
        trap - EXIT
    fi
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
