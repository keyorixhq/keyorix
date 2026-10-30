#!/usr/bin/env bash
# scripts/release-qa/backup_inplace_upgrade_check.sh -- a database written by an
# OLD release, upgraded IN PLACE by the current binary without starting the
# current server, then backed up and restored by the current binary
# (ADMIN-BACKUP-TAILS-1, follow-up of UPGRADE-RESTORE-COMPAT-1). Native
# binaries only, no Docker.
#
# The window it covers: v0.95.x kept each webhook URL in the plaintext
# notification_channels.url column; the current server moves it into
# url_enc/url_meta at its first start. `admin migrate` upgrades the schema but
# does not run that backfill, so a backup taken between the two used to drop the
# URL silently. The current backup now either carries the value or refuses with
# "start the server once to finish the upgrade migrations, then back up"; this
# script accepts either, and fails if the backup succeeds and the restored
# channel lost its URL.
#
# Per leg (SQLite always; PostgreSQL when two DSNs are given):
#   1. OLD binary: fresh install, TOTP admin, project + secret, webhook
#      channel; stop the server.
#   2. HEAD binary: `admin migrate` the same database in place (server NOT
#      started). SQLite: reports how many channels still hold a plaintext URL.
#   3. HEAD `admin backup`. If it refuses with the remedy above, do what the
#      message says (start HEAD's server once, stop it) and back up again.
#   4. HEAD `admin restore` into a fresh target, `admin verify-audit`, a second
#      `admin backup` of the target whose per-table row counts must equal the
#      first archive's, then start the target's server, log in with TOTP and
#      read the channel back (its scheme://host must match what was added).
#
# Usage: backup_inplace_upgrade_check.sh <work-dir> <old-tag> \
#          [<pg-source-dsn> <pg-target-dsn>]
#   e.g. backup_inplace_upgrade_check.sh .scratch/bip v0.95.3 \
#          "$(kpg dsn x_src)" "$(kpg dsn x_dst)"
# Both DSNs must name their own EMPTY database: the OLD binary migrates the
# source, and restore refuses a populated target. Env: KEYORIX_QA_PORT
# (default 18097). Binaries are built into <work-dir>/bin and reused when
# present. Container and Helm variants are not covered here (pending e2e VM).
set -euo pipefail

[ $# -eq 2 ] || [ $# -eq 4 ] || { sed -n '2,38p' "$0" >&2; exit 2; }
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLIENT="$REPO_ROOT/scripts/release-qa/restore_compat_client.py"
mkdir -p "$1/bin"
WORK="$(cd "$1" && pwd)"
TAG="$2"
PG_SRC_DSN="${3:--}"
PG_DST_DSN="${4:--}"
SERVER_PORT="${KEYORIX_QA_PORT:-18097}"
SERVER_URL="http://127.0.0.1:$SERVER_PORT"

fail() { echo "" >&2; echo "BACKUP-INPLACE FAILED: $1" >&2; exit 1; }
step() { echo "==> $1" >&2; }

build() { # <label> <source-dir>
    step "building $1"
    (cd "$2" && go build -o "$WORK/bin/server-$1" ./server) || return 1
    (cd "$2/cli" && GOWORK=off go build -o "$WORK/bin/cli-$1" .) || return 1
}
build head "$REPO_ROOT" || fail "build of HEAD failed"
if [ ! -x "$WORK/bin/server-$TAG" ]; then
    src="$WORK/src-$TAG"
    rm -rf "$src" && mkdir -p "$src"
    git -C "$REPO_ROOT" archive "$TAG" | tar -x --exclude='.claude' -C "$src" || fail "git archive $TAG"
    build "$TAG" "$src" || fail "build of $TAG failed"
fi
OLD_SERVER_BIN="$WORK/bin/server-$TAG"
OLD_CLI_BIN="$WORK/bin/cli-$TAG"
NEW_SERVER_BIN="$WORK/bin/server-head"
NEW_CLI_BIN="$WORK/bin/cli-head"

SERVER_PID=""
cleanup() { if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; }
trap cleanup EXIT

start_server() { # <bin> <cfg> <label>
    local bin="$1" cfg="$2" label="$3"
    step "start $label server (log: $PWD/server-$label.log)"
    KEYORIX_CONFIG_PATH="$cfg" "$bin" > "$PWD/server-$label.log" 2>&1 &
    SERVER_PID=$!
    for _ in $(seq 1 120); do
        if curl -fs "$SERVER_URL/health" >/dev/null 2>&1; then return 0; fi
        kill -0 "$SERVER_PID" 2>/dev/null || break
        sleep 0.5
    done
    tail -40 "$PWD/server-$label.log" >&2
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

export KEYORIX_QA_TOTP_STATE="$WORK/totp-last-step"
export HOME="$WORK/home"
mkdir -p "$HOME"
export KEYORIX_MASTER_PASSWORD="bipc-master-password-$$-${RANDOM}"
BOOTSTRAP_TOKEN="$(openssl rand -hex 32)"
ADMIN_PASSWORD="Bipc-Test-Op3rator-Passw0rd!-$$-${RANDOM}"
SECRET_VALUE="bipc-secret-value-$$-${RANDOM}"
# An IP literal: the channel validator resolves hostnames to refuse private
# targets, and a sandboxed run has no DNS. TEST-NET-3, never delivered to.
CHANNEL_URL="https://203.0.113.10/keyorix-qa/bipc-$$"

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

# compare_counts <old-counts> <new-counts> <label>: audit_events and
# system_metadata may grow (restore and backup append their own rows), every
# other table must match exactly.
compare_counts() {
    local t n m mismatch=0
    while read -r t n; do
        m="$(awk -v t="$t" '$1==t {print $2}' "$2")"
        if [ "$t" = audit_events ] || [ "$t" = system_metadata ]; then
            if [ -z "$m" ] || [ "$m" -lt "$n" ]; then
                echo "  row count $t: before=$n after=${m:-missing} (may grow, never shrink)" >&2
                mismatch=1
            fi
        elif [ "${m:-missing}" != "$n" ]; then
            echo "  row count $t: before=$n after=${m:-missing}" >&2
            mismatch=1
        fi
    done < "$1"
    [ "$mismatch" -eq 0 ] || fail "$3: per-table row counts differ between the in-place backup and the restored database"
}

# leg <label> <source-storage-yaml> <target-storage-yaml>
leg() {
    local label="$1" src_storage="$2" dst_storage="$3"
    local src="$WORK/$label/source" dst="$WORK/$label/target" token got
    rm -rf "${WORK:?}/$label"
    mkdir -p "$src" "$dst"

    echo "============================================================" >&2
    echo " LEG $label, PHASE 1: OLD $TAG seeds the source database" >&2
    echo "============================================================" >&2
    cd "$src"
    "$OLD_SERVER_BIN" admin init --config ./keyorix.yaml >/dev/null || fail "$label: old admin init"
    write_config ./keyorix.yaml "$src_storage"
    "$OLD_SERVER_BIN" admin encryption init --config ./keyorix.yaml >/dev/null || fail "$label: old encryption init"
    "$OLD_SERVER_BIN" admin migrate --config ./keyorix.yaml >/dev/null || fail "$label: old migrate"
    KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" start_server "$OLD_SERVER_BIN" ./keyorix.yaml old
    KEYORIX_ADMIN_PASSWORD="$ADMIN_PASSWORD" KEYORIX_BOOTSTRAP_TOKEN="$BOOTSTRAP_TOKEN" \
        "$OLD_CLI_BIN" system init --server "$SERVER_URL" --admin-username admin \
        --admin-email admin@release-qa.local >/dev/null || fail "$label: old system init"
    token="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD")" || fail "$label: old admin login"
    MFA_SECRET="$(python3 "$CLIENT" enroll-mfa "$SERVER_URL" "$token" "$ADMIN_PASSWORD")" || fail "$label: old mfa enrol"
    token="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD" "$MFA_SECRET")" || fail "$label: old MFA login"
    export KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$token"
    "$OLD_CLI_BIN" project create --name bipc-project >/dev/null || fail "$label: old project create"
    (umask 077 && printf '%s' "$SECRET_VALUE" > ./secret-value.txt)
    "$OLD_CLI_BIN" secret create --name bipc-secret --from-file ./secret-value.txt \
        --project 1 --environment 1 >/dev/null || fail "$label: old secret create"
    "$OLD_CLI_BIN" notification channel add bipc-hook --type webhook --url "$CHANNEL_URL" \
        --events anomaly.detected >/dev/null || fail "$label: old notification channel add"
    stop_server
    unset KEYORIX_TOKEN

    echo "============================================================" >&2
    echo " LEG $label, PHASE 2: HEAD upgrades in place (server NOT started)" >&2
    echo "============================================================" >&2
    "$NEW_SERVER_BIN" admin migrate --config ./keyorix.yaml >/dev/null || fail "$label: head admin migrate (in place)"
    if [ "$label" = sqlite ]; then
        got="$(python3 - ./keyorix.db <<'PY'
import sqlite3, sys
db = sqlite3.connect(sys.argv[1])
cols = [r[1] for r in db.execute("PRAGMA table_info(notification_channels)")]
if "url" not in cols:
    print("0 (no legacy url column: this tag already stores the URL encrypted)")
else:
    n = db.execute("SELECT count(*) FROM notification_channels WHERE url IS NOT NULL AND url <> ''").fetchone()[0]
    print(f"{n} (legacy url column present)")
PY
)" || fail "$label: reading the upgraded SQLite database"
        step "$label: channels holding a plaintext legacy URL after the in-place migrate: $got"
    fi

    echo "============================================================" >&2
    echo " LEG $label, PHASE 3: HEAD backs up the upgraded database" >&2
    echo "============================================================" >&2
    local archive="$src/backup.tar.gz" refused=no
    if "$NEW_SERVER_BIN" admin backup --config ./keyorix.yaml --output "$archive" > "$src/backup-1.log" 2>&1; then
        step "$label: backup succeeded straight after the in-place migrate"
    elif grep -q "start the server once to finish the upgrade migrations, then back up" "$src/backup-1.log"; then
        refused=yes
        [ ! -e "$archive" ] || fail "$label: the refused backup left an archive behind"
        step "$label: backup refused as documented; starting HEAD's server once, as the message says"
        start_server "$NEW_SERVER_BIN" ./keyorix.yaml head-first-start
        stop_server
        "$NEW_SERVER_BIN" admin backup --config ./keyorix.yaml --output "$archive" > "$src/backup-2.log" 2>&1 \
            || { tail -20 "$src/backup-2.log" >&2; fail "$label: backup after the first server start"; }
    else
        tail -20 "$src/backup-1.log" >&2
        fail "$label: backup failed for a reason other than the documented one"
    fi
    python3 "$CLIENT" manifest-counts "$archive" | sort > "$src/counts-backup.txt"
    grep -qE "^notification_channels [1-9]" "$src/counts-backup.txt" || fail "$label: the archive has no notification_channels rows"

    echo "============================================================" >&2
    echo " LEG $label, PHASE 4: HEAD restores into a fresh target" >&2
    echo "============================================================" >&2
    cd "$dst"
    write_config ./keyorix.yaml "$dst_storage"
    "$NEW_SERVER_BIN" admin restore --config ./keyorix.yaml --input "$archive" > "$dst/restore.log" 2>&1 \
        || { tail -30 "$dst/restore.log" >&2; fail "$label: admin restore"; }
    "$NEW_SERVER_BIN" admin verify-audit --config ./keyorix.yaml > "$dst/verify-audit.log" 2>&1 \
        || { tail -30 "$dst/verify-audit.log" >&2; fail "$label: admin verify-audit"; }
    step "$label: restore OK, audit chain $(grep -oE 'VALID|BROKEN' "$dst/verify-audit.log" | head -1)"
    "$NEW_SERVER_BIN" admin backup --config ./keyorix.yaml --output "$dst/after.tar.gz" >/dev/null \
        || fail "$label: admin backup of the restored database"
    python3 "$CLIENT" manifest-counts "$dst/after.tar.gz" | sort > "$dst/counts-after.txt"
    compare_counts "$src/counts-backup.txt" "$dst/counts-after.txt" "$label"
    step "$label: row counts match ($(wc -l < "$src/counts-backup.txt" | tr -d ' ') tables)"

    start_server "$NEW_SERVER_BIN" ./keyorix.yaml "$label-target"
    token="$(python3 "$CLIENT" login "$SERVER_URL" admin "$ADMIN_PASSWORD" "$MFA_SECRET")" \
        || fail "$label: admin login with TOTP on the restored target"
    got="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$token" "$NEW_CLI_BIN" secret get --id 1 --show-value)" \
        || fail "$label: secret get"
    echo "$got" | grep -qF "$SECRET_VALUE" || fail "$label: secret value differs after restore: $got"
    got="$(KEYORIX_SERVER="$SERVER_URL" KEYORIX_TOKEN="$token" "$NEW_CLI_BIN" notification channel get bipc-hook)" \
        || fail "$label: notification channel get"
    # A read shows only scheme://host of the URL (the rest is the credential,
    # #3438); a URL lost in the backup reads back empty.
    echo "$got" | grep -E '^url:' | grep -qF "$(printf %s "$CHANNEL_URL" | cut -d/ -f1-3)/" \
        || fail "$label: the channel URL did not survive backup and restore: $got"
    step "$label: channel URL survived (backup refused first: $refused)"
    stop_server
    echo "LEG PASSED: $label (refused-then-remedied: $refused)" >&2
}

leg sqlite "  type: sqlite
  database:
    path: \"$WORK/sqlite/source/keyorix.db\"" "  type: sqlite
  database:
    path: \"$WORK/sqlite/target/keyorix.db\""
if [ "$PG_SRC_DSN" != "-" ]; then
    leg postgres "  type: postgres
  database:
    dsn: \"$PG_SRC_DSN\"" "  type: postgres
  database:
    dsn: \"$PG_DST_DSN\""
else
    echo "postgres leg skipped (no DSNs given)" >&2
fi
echo "BACKUP-INPLACE PASSED: $TAG -> head"
