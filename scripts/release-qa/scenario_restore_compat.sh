#!/usr/bin/env bash
# scripts/release-qa/scenario_restore_compat.sh -- an OLD release binary's
# `admin backup`, restored by a NEW binary on SQLite and on PostgreSQL
# (#3452, UPGRADE-RESTORE-COMPAT-1). Native binaries only, no Docker.
#
# Phase 1 (OLD binary, SQLite): fresh install, then seed every row family
# an upgrade has historically broken: an admin with TOTP enrolled, a second
# user, a project + secret, a share of that secret, a webhook notification
# channel (its url column changed shape with at-rest encryption, #2468), and
# the audit chain those writes produce. Stop the server, `admin backup`.
#
# Phase 2 (NEW binary, once per target backend): `admin restore` the OLD
# archive, `admin verify-audit`, then a fresh offline `admin backup` of the
# restored database whose manifest row counts must equal the OLD archive's
# (per table; tables the new schema added are reported, not failed), start
# the server, log in with password + TOTP, read the secret (value must be
# byte-identical), and read the notification channel back (url identical).
#
# Usage: scenario_restore_compat.sh <old-server-bin> <old-cli-bin> \
#          <new-server-bin> <new-cli-bin> <postgres-dsn|-> [work-dir]
#
# <postgres-dsn> must point at an EMPTY, dedicated database (`kpg dsn <name>`
# in a sandboxed session); pass "-" to run the SQLite leg only.
# Env: KEYORIX_QA_PORT (default 18096).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT="$SCRIPT_DIR/restore_compat_client.py"
OLD_SERVER_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
OLD_CLI_BIN="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
NEW_SERVER_BIN="$(cd "$(dirname "$3")" && pwd)/$(basename "$3")"
NEW_CLI_BIN="$(cd "$(dirname "$4")" && pwd)/$(basename "$4")"
PG_DSN="$5"
WORK_DIR="${6:-$(mktemp -d)}"
SERVER_PORT="${KEYORIX_QA_PORT:-18096}"
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() { echo "" >&2; echo "RESTORE-COMPAT FAILED: $1" >&2; exit 1; }
step() { echo "==> $1" >&2; }

for bin in "$OLD_SERVER_BIN" "$OLD_CLI_BIN" "$NEW_SERVER_BIN" "$NEW_CLI_BIN"; do
    [ -x "$bin" ] || fail "binary not found/executable: $bin"
done
mkdir -p "$WORK_DIR"
WORK_DIR="$(cd "$WORK_DIR" && pwd)"
SERVER_PID=""
cleanup() { if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

start_server() {
    local bin="$1" cfg="$2" label="$3"
    step "start $label server (log: $WORK_DIR/server-$label.log)"
    KEYORIX_CONFIG_PATH="$cfg" "$bin" > "$WORK_DIR/server-$label.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 120); do
        if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then return 0; fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    tail -40 "$WORK_DIR/server-$label.log" >&2
    fail "keyorix-server ($label) did not become healthy"
}
stop_server() {
    [ -n "$SERVER_PID" ] || return 0
    kill "$SERVER_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.25
    done
    SERVER_PID=""
}

export KEYORIX_QA_TOTP_STATE="$WORK_DIR/totp-last-step"
export HOME="$WORK_DIR/home"
mkdir -p "$HOME"
# KEYORIX_QA_MASTER_PASSWORD / KEYORIX_QA_SECRET_VALUE / KEYORIX_QA_CHANNEL_URL
# pin the values when the OLD archive is kept as a test fixture
# (server/admin/testdata/v0.95.3-backup.tar.gz was made this way).
export KEYORIX_MASTER_PASSWORD="${KEYORIX_QA_MASTER_PASSWORD:-qarc-master-password-$$-${RANDOM}}"
BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
ADMIN_PASSWORD="Qarc-Test-Op3rator-Passw0rd!-$$-${RANDOM}"
SECRET_VALUE="${KEYORIX_QA_SECRET_VALUE:-qarc-secret-value-$$-${RANDOM}}"
# An IP literal: the channel validator resolves hostnames to refuse private
# targets, and a sandboxed or air-gapped run has no DNS. TEST-NET-3, never
# delivered to (the channel only listens for anomaly.detected).
CHANNEL_URL="${KEYORIX_QA_CHANNEL_URL:-https://203.0.113.10/keyorix-qa/$$}"

write_config() { # <file> <storage-yaml-block>
    cat > "$1" <<EOF
storage:
$2
  encryption:
    enabled: true
    dek_path: "keys/dek.key"
    salt_path: "keys/kek.salt"
server:
  http:
    enabled: true
    port: "$SERVER_PORT"
    protocol_versions: ["1.1"]
    tls:
      enabled: false
EOF
}

echo "============================================================" >&2
echo " PHASE 1: OLD binary $(basename "$OLD_SERVER_BIN") -- seed + backup (SQLite)" >&2
echo "============================================================" >&2
OLD_DIR="$WORK_DIR/old"
mkdir -p "$OLD_DIR"
cd "$OLD_DIR"
"$OLD_SERVER_BIN" admin init --config ./keyorix.yaml >/dev/null || fail "old admin init"
# admin init's template enables TLS from v0.96.0 on; the scenario talks plain
# HTTP on loopback, so replace it with the same minimal config phase 2 uses
# (admin init's own key paths, which the archive records).
write_config ./keyorix.yaml "  type: sqlite
  database:
    path: \"$OLD_DIR/keyorix.db\""
"$OLD_SERVER_BIN" admin encryption init --config ./keyorix.yaml >/dev/null || fail "old encryption init"
"$OLD_SERVER_BIN" admin migrate --config ./keyorix.yaml >/dev/null || fail "old migrate"
KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" start_server "$OLD_SERVER_BIN" ./keyorix.yaml old
KEYORIX_ADMIN_PASSWORD="$ADMIN_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
    "$OLD_CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
    --admin-email admin@release-qa.local >/dev/null || fail "old system init"

step "old: admin enrols TOTP, logs in with it"
TOKEN="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD")" || fail "old admin login"
MFA_SECRET="$(python3 "$CLIENT" enroll-mfa "$SERVER_URL" "$TOKEN" "$ADMIN_PASSWORD")" || fail "old mfa enrol"
TOKEN="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD" "$MFA_SECRET")" || fail "old MFA login"
export KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$TOKEN"

step "old: project, secret, second user, share, notification channel"
"$OLD_CLI_BIN" project create --name qarc-project >/dev/null || fail "old project create"
(umask 077 && printf '%s' "$SECRET_VALUE" > ./secret-value.txt)
"$OLD_CLI_BIN" secret create --name qarc-secret --from-file ./secret-value.txt \
    --project 1 --environment 1 >/dev/null || fail "old secret create"
KEYORIX_INITIAL_PASSWORD="Qarc-Second-User-Passw0rd!-$$" "$OLD_CLI_BIN" user create \
    --username qarc-bob --email bob@release-qa.local >/dev/null || fail "old user create"
BOB_OUT="$("$OLD_CLI_BIN" user get --email bob@release-qa.local 2>&1)" || fail "old user get: $BOB_OUT"
BOB_ID="$(echo "$BOB_OUT" | grep -iE '^[[:space:]]*"?id"?[[:space:]]*[:=]' | head -1 | grep -oE '[0-9]+' | head -1 || true)"
[ -n "$BOB_ID" ] || fail "could not read the second user's id from: $BOB_OUT"
# A user share needs both the owner and the recipient to be members of the
# secret's project (a global admin role is not project membership).
"$OLD_CLI_BIN" rbac assign-role --user admin@release-qa.local --role project_admin --project default >/dev/null \
    || fail "old rbac assign-role (admin)"
"$OLD_CLI_BIN" rbac assign-role --user bob@release-qa.local --role project_viewer --project default >/dev/null \
    || fail "old rbac assign-role"
python3 "$CLIENT" post "$SERVER_URL" "$TOKEN" /api/v1/secrets/1/share \
    "{\"secret_id\":1,\"recipient_id\":$BOB_ID,\"permission\":\"read\"}" >/dev/null || fail "old share create"
"$OLD_CLI_BIN" notification channel add qarc-hook --type webhook --url "$CHANNEL_URL" \
    --events anomaly.detected >/dev/null \
    || fail "old notification channel add"
stop_server
unset KEYORIX_TOKEN

step "old: admin backup"
OLD_ARCHIVE="$OLD_DIR/backup.tar.gz"
"$OLD_SERVER_BIN" admin backup --config ./keyorix.yaml --output "$OLD_ARCHIVE" >/dev/null || fail "old admin backup"
python3 "$CLIENT" manifest-counts "$OLD_ARCHIVE" | sort > "$WORK_DIR/counts-old.txt"
for t in notification_channels share_records users secret_nodes mfa_secrets audit_events; do
    grep -qE "^$t [1-9]" "$WORK_DIR/counts-old.txt" || echo "warning: old archive has no $t rows (seed did not reach it?)" >&2
done

# restore_leg <label> <storage-yaml-block>
restore_leg() {
    local label="$1" storage="$2" dir="$WORK_DIR/$1"
    echo "============================================================" >&2
    echo " PHASE 2 ($label): NEW binary restores the OLD archive" >&2
    echo "============================================================" >&2
    mkdir -p "$dir"
    cd "$dir"
    write_config ./keyorix.yaml "$storage"
    "$NEW_SERVER_BIN" admin restore --config ./keyorix.yaml --input "$OLD_ARCHIVE" \
        > "$dir/restore.log" 2>&1 || { tail -30 "$dir/restore.log" >&2; fail "$label: admin restore"; }
    step "$label: restore OK"
    "$NEW_SERVER_BIN" admin verify-audit --config ./keyorix.yaml > "$dir/verify-audit.log" 2>&1 \
        || { tail -30 "$dir/verify-audit.log" >&2; fail "$label: admin verify-audit"; }
    step "$label: audit chain $(grep -oE 'VALID|BROKEN' "$dir/verify-audit.log" | head -1)"

    "$NEW_SERVER_BIN" admin backup --config ./keyorix.yaml --output "$dir/after.tar.gz" >/dev/null \
        || fail "$label: admin backup of the restored database"
    python3 "$CLIENT" manifest-counts "$dir/after.tar.gz" | sort > "$dir/counts-new.txt"
    # Restore itself appends to two tables: audit_events (its own
    # admin.restore_completed / admin.backup_created events) and
    # system_metadata (the restoring binary's schema-epoch rows). Those may
    # grow; every other table must match the OLD archive exactly.
    local mismatch=0 t n m
    while read -r t n; do
        m="$(awk -v t="$t" '$1==t {print $2}' "$dir/counts-new.txt")"
        if [ "$t" = audit_events ] || [ "$t" = system_metadata ]; then
            if [ -z "$m" ] || [ "$m" -lt "$n" ]; then
                echo "  row count $t: old=$n new=${m:-missing} (may grow, never shrink)" >&2
                mismatch=1
            fi
        elif [ "${m:-missing}" != "$n" ]; then
            echo "  row count $t: old=$n new=${m:-missing}" >&2
            mismatch=1
        fi
    done < "$WORK_DIR/counts-old.txt"
    [ "$mismatch" -eq 0 ] || fail "$label: per-table row counts differ from the OLD archive"
    step "$label: row counts match the OLD archive ($(wc -l < "$WORK_DIR/counts-old.txt" | tr -d ' ') tables)"

    start_server "$NEW_SERVER_BIN" ./keyorix.yaml "$label"
    local token got
    token="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD" "$MFA_SECRET")" \
        || fail "$label: admin login with TOTP"
    step "$label: password + TOTP login OK"
    got="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$token" "$NEW_CLI_BIN" secret get --id 1 --show-value)" \
        || fail "$label: secret get"
    echo "$got" | grep -qF "$SECRET_VALUE" || fail "$label: secret value differs after restore: $got"
    step "$label: secret value byte-identical"
    got="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$token" "$NEW_CLI_BIN" notification channel get qarc-hook)" \
        || fail "$label: notification channel get"
    # Since #3438 a read shows only scheme://host of the URL (the rest is the
    # credential). The read decrypts url_enc fail-closed, so a matching host
    # means the restored ciphertext decrypts under the restored keys.
    echo "$got" | grep -E '^url:' | grep -qF "$(printf %s "$CHANNEL_URL" | cut -d/ -f1-3)/" \
        || fail "$label: notification channel url differs after restore: $got"
    step "$label: notification channel url decrypts (host matches)"
    stop_server
    echo "LEG PASSED: $label" >&2
}

restore_leg sqlite "  type: sqlite
  database:
    path: \"$WORK_DIR/sqlite/keyorix.db\""
if [ "$PG_DSN" != "-" ]; then
    restore_leg postgres "  type: postgres
  database:
    dsn: \"$PG_DSN\""
else
    echo "postgres leg skipped (no DSN given)" >&2
fi
echo "RESTORE-COMPAT PASSED: $(basename "$OLD_SERVER_BIN") -> $(basename "$NEW_SERVER_BIN")"
