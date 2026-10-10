#!/bin/sh
set -e

# ---------------------------------------------------------------------------
# Container preparation (SECURE-DEFAULT-1). Every step is opt-in through the
# environment, so a deployment that sets none of these variables behaves
# exactly as before.
#
# KEYORIX_CONFIG_SOURCE: a read-only, orchestrator-mounted config. A compose
#   bind mount keeps the host's owner and mode (typically uid 1000, 0664), which
#   the startup file-permission check and `admin validate --posture` flag
#   (#2922). Copy it to KEYORIX_CONFIG_PATH as this user at 0600 on every
#   start, so an edit to the source takes effect on the next restart.
# KEYORIX_INIT_SECURE_FILES=true: generate the TLS certificate/key and metrics
#   token the config references, if missing (`admin init --secure-files`;
#   existing files are kept). KEYORIX_TLS_DNS_NAMES adds space-separated DNS
#   names to a generated certificate; KEYORIX_PUBLIC_CA_FILE receives a 0644
#   copy of the certificate for a proxy that must trust it (the web container).
# KEYORIX_LOCAL_URL / KEYORIX_LOCAL_CA_FILE: how this script reaches its own
#   server (default http://localhost:8080). With TLS on, set the https URL and
#   the certificate to verify it with; it is used only for this script's own
#   requests, never exported to the server (Go would read SSL_CERT_FILE too).
#
# With arguments (`docker compose run --rm backend ./keyorix-server admin ...`)
# the config copy is made and the arguments are run instead of the server.
# ---------------------------------------------------------------------------
if [ -n "$KEYORIX_CONFIG_SOURCE" ]; then
    : "${KEYORIX_CONFIG_PATH:?KEYORIX_CONFIG_SOURCE is set, so KEYORIX_CONFIG_PATH must name the private copy}"
    (umask 077 && cp "$KEYORIX_CONFIG_SOURCE" "$KEYORIX_CONFIG_PATH.tmp")
    chmod 600 "$KEYORIX_CONFIG_PATH.tmp"
    mv -f "$KEYORIX_CONFIG_PATH.tmp" "$KEYORIX_CONFIG_PATH"
fi

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

if [ "$KEYORIX_INIT_SECURE_FILES" = "true" ]; then
    set --
    if [ -n "$KEYORIX_CONFIG_PATH" ]; then
        set -- --config "$KEYORIX_CONFIG_PATH"
    fi
    for name in $KEYORIX_TLS_DNS_NAMES; do
        set -- "$@" --tls-dns-name "$name"
    done
    ./keyorix-server admin init --secure-files "$@"
    if [ -n "$KEYORIX_PUBLIC_CA_FILE" ]; then
        : "${KEYORIX_LOCAL_CA_FILE:?KEYORIX_PUBLIC_CA_FILE needs KEYORIX_LOCAL_CA_FILE (the certificate to copy)}"
        (umask 022 && cp "$KEYORIX_LOCAL_CA_FILE" "$KEYORIX_PUBLIC_CA_FILE.tmp")
        chmod 644 "$KEYORIX_PUBLIC_CA_FILE.tmp"
        mv -f "$KEYORIX_PUBLIC_CA_FILE.tmp" "$KEYORIX_PUBLIC_CA_FILE"
    fi
fi

LOCAL_URL="${KEYORIX_LOCAL_URL:-http://localhost:8080}"
# local_wget: wget against this container's own server, verifying its TLS
# certificate with KEYORIX_LOCAL_CA_FILE when one is set.
local_wget() {
    if [ -n "$KEYORIX_LOCAL_CA_FILE" ]; then
        SSL_CERT_FILE="$KEYORIX_LOCAL_CA_FILE" wget "$@"
    else
        wget "$@"
    fi
}

echo "Starting Keyorix server..."

# Run the server in the background so we can perform an optional first-boot admin
# bootstrap once it is healthy, then hand the process the foreground.
./keyorix-server &
SERVER_PID=$!

# Always re-foreground the server on exit so signals propagate to it.
trap 'kill -TERM "$SERVER_PID" 2>/dev/null' TERM INT

echo "Waiting for server to be ready..."
for _ in $(seq 1 30); do
    if local_wget --quiet --spider "$LOCAL_URL/health" 2>/dev/null; then
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
        echo "WARN: KEYORIX_ADMIN_PASSWORD is set but KEYORIX_BOOTSTRAP_TOKEN is not — skipping"
        echo "WARN: auto-bootstrap (the server-generated random token can't be read back here)."
        echo "WARN: Set KEYORIX_BOOTSTRAP_TOKEN, or initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
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
        # Self-contained (entrypoint_test.sh runs this block on its own): verify
        # this server's own certificate when KEYORIX_LOCAL_CA_FILE is set; the
        # subshell keeps SSL_CERT_FILE away from everything else.
        (
            if [ -n "$KEYORIX_LOCAL_CA_FILE" ]; then SSL_CERT_FILE="$KEYORIX_LOCAL_CA_FILE"; export SSL_CERT_FILE; fi
            wget --quiet -O- \
                --header='Content-Type: application/json' \
                --header="X-Keyorix-Bootstrap-Token: $KEYORIX_BOOTSTRAP_TOKEN" \
                --post-file="$BOOTSTRAP_PAYLOAD_FILE" \
                "${KEYORIX_LOCAL_URL:-http://localhost:8080}/system/init"
        ) 2>/dev/null || \
            echo "Bootstrap call failed (server may already be initialised) — continuing."
        rm -rf "$BOOTSTRAP_TMPDIR"
        trap - EXIT
    fi
else
    echo "KEYORIX_ADMIN_PASSWORD not set — skipping auto-bootstrap."
    echo "Initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
