#!/bin/sh
set -e

echo "Starting Keyorix server..."

# --- BEGIN secret-file resolution (tested by deploy/hardening/entrypoint_secret_file_test.go) ---
# The two secrets this script reads itself for the first-boot admin bootstrap may be
# supplied as KEYORIX_ADMIN_PASSWORD_FILE / KEYORIX_BOOTSTRAP_TOKEN_FILE (Docker
# secrets, a Kubernetes Secret volume) instead of the environment. Same rules as the
# server applies to its own secrets (internal/secretenv): the file is read with ONE
# trailing newline stripped; both X and X_FILE set, or an unreadable/empty file, is
# fatal (no silent precedence, no fall-through); no value is ever printed. The result
# is a plain shell variable and is deliberately NOT exported, so the server started
# below does not get it in its environment.
resolve_file_secret() {
    _name="$1"
    eval "_direct=\${$_name:-}"
    eval "_path=\${${_name}_FILE:-}"
    if [ -n "$_direct" ] && [ -n "$_path" ]; then
        echo "FATAL: both ${_name} and ${_name}_FILE are set; set exactly one" >&2
        return 1
    fi
    if [ -z "$_path" ]; then
        return 0
    fi
    if [ ! -f "$_path" ] || [ ! -r "$_path" ]; then
        echo "FATAL: ${_name}_FILE=${_path} is not a readable regular file" >&2
        return 1
    fi
    # The trailing "x" keeps command substitution from eating every trailing newline.
    _val=$(cat "$_path"; printf x)
    _val=${_val%x}
    _nl='
'
    _cr=$(printf '\r')
    case $_val in
        *"$_cr$_nl") _val=${_val%"$_cr$_nl"} ;;
        *"$_nl") _val=${_val%"$_nl"} ;;
    esac
    if [ -z "$_val" ]; then
        echo "FATAL: ${_name}_FILE=${_path} is empty" >&2
        return 1
    fi
    eval "$_name=\$_val"
}
resolve_file_secret KEYORIX_ADMIN_PASSWORD || exit 1
resolve_file_secret KEYORIX_BOOTSTRAP_TOKEN || exit 1
# --- END secret-file resolution ---

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
    echo "Initialise manually: \`keyorix system init --server http://<host>:8080\`" # NOSONAR -- documentation string, not a network connection
fi

# Hand the server the foreground.
wait "$SERVER_PID"
