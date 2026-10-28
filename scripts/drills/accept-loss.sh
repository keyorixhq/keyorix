#!/usr/bin/env bash
# shellcheck disable=SC2016  # the bash -c body below is meant to be single-quoted
# scripts/drills/accept-loss.sh -- accepting a proven audit-row loss (AUDIT-ACCEPT-LOSS-1).
#
# The real binaries, the way an operator drives them (docs/operator/audit-chain-break-runbook.md §7):
#   1. a certified deployment reads VALID online and offline;
#   2. one audit row is deleted from the database: online and offline read BROKEN;
#   3. `admin audit accept-loss` refuses a wrong id and writes nothing without --confirm, then
#      seals the gap with --confirm (bound to an export-checkpoint anchor taken before the loss);
#   4. after a restart the online status reads not_proven, then SEALED (never valid), and the
#      offline verify-audit exits 4 (SEALED);
#   5. rotate-kek: the seal is carried over, a fresh checkpoint is written, and both verifiers
#      still read SEALED under the new key (offline with the newly exported key).
#
# Usage: [DRILL_BACKEND=postgres DRILL_PG_DSN_FILE=a.txt] [DRILL_SERVER_BIN=... DRILL_CLI_BIN=...] \
#        scripts/drills/accept-loss.sh
# Postgres needs psql on PATH (to delete the audit row the way an attacker or a botched cleanup would).
set -euo pipefail
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

drill_begin accept-loss
I=inst
P="$(drill_port 31)"
d="$DRILL_DIR/$I"

# db_exec <sql>: run SQL against the instance database behind keyorix's back.
db_exec() {
    if [ "$DRILL_BACKEND" = "postgres" ]; then
        PGPASSWORD="$PG_PASS" psql "postgres://$PG_USER@$PG_HOST:$PG_PORT/$PG_DB?sslmode=disable" -v ON_ERROR_STOP=1 -q -c "$1"
    else
        sqlite3 "$d/keyorix.db" "$1"
    fi
}

# online_status: the status field of GET /api/v1/audit/verify (incremental mode), as the
# logged-in admin (login_admin after each srv_start).
online_status() {
    cli "$I" "$P" audit verify --json 2>/dev/null | jq -r '.status // (if .valid then "valid" else "broken" end)'
}

# wait_status <want> <seconds>: poll the online status (the checkpoint scheduler ticks every 2s).
wait_status() {
    local want="$1" secs="$2" got="" _
    for _ in $(seq 1 "$secs"); do
        got="$(online_status || true)"
        [ "$got" = "$want" ] && { ok "online status: $got"; return 0; }
        sleep 1
    done
    fail "online status is '$got' after ${secs}s, want '$want'"
}

# offline <want-exit> [args]: verify-audit with the checkpoint key; prints the verdict line.
offline() {
    local want="$1" rc=0 out
    shift
    out="$(inst_admin "$I" verify-audit --checkpoint-key-file ./ckpt.key "$@" 2>&1)" || rc=$?
    [ "$rc" = "$want" ] || { echo "$out" >&2; fail "verify-audit exited $rc, want $want"; }
    ok "verify-audit exit $rc: $(grep -m1 '^Verdict:' <<<"$out")"
}

step "1. provision with a 2s checkpoint schedule, seed, certify"
inst_new "$I" "$P"
printf '\naudit_checkpoints:\n  schedule: "2s"\n' >>"$d/keyorix.yaml"
srv_start "$I" "$P"
seed_data "$I" "$P"
login_admin "$I" "$P"
cli "$I" "$P" audit checkpoint >/dev/null || fail "audit checkpoint failed"
wait_status valid 60
srv_stop "$I"
inst_admin "$I" audit export-checkpoint-key --output ./ckpt.key >/dev/null || fail "export-checkpoint-key failed"
inst_admin "$I" audit export-checkpoint --output ./anchor-before-loss.json >/dev/null || fail "export-checkpoint failed"
offline 0

step "2. delete one audit row behind keyorix's back"
LOST=10
db_exec "DELETE FROM audit_events WHERE id = $LOST" >/dev/null
offline 1
srv_start "$I" "$P"
login_admin "$I" "$P"
wait_status broken 60
srv_stop "$I"

step "3. accept-loss: wrong id refused, nothing written without --confirm, then sealed"
EVIDENCE="$(shasum -a 256 "$d/ckpt.key" | cut -d' ' -f1)"
common=(--operator drill-oncall --reason "DRILL-1: row $LOST deleted" --evidence-sha256 "$EVIDENCE")
if inst_admin "$I" audit accept-loss --first-broken-id $((LOST + 2)) "${common[@]}" --confirm >"$DRILL_DIR/al-wrong.log" 2>&1; then
    fail "accept-loss accepted a wrong id"
fi
grep -q "not at #$((LOST + 2))" "$DRILL_DIR/al-wrong.log" || { cat "$DRILL_DIR/al-wrong.log" >&2; fail "wrong id: unexpected refusal"; }
ok "wrong id refused: $(grep -m1 'not at' "$DRILL_DIR/al-wrong.log" | cut -c1-120)"
if inst_admin "$I" audit accept-loss --first-broken-id $((LOST + 1)) "${common[@]}" --anchor ./anchor-before-loss.json \
    >"$DRILL_DIR/al-dry.log" 2>&1; then
    fail "accept-loss wrote without --confirm"
fi
grep -q "nothing was written" "$DRILL_DIR/al-dry.log" || { cat "$DRILL_DIR/al-dry.log" >&2; fail "dry run: no 'nothing was written'"; }
offline 1
ok "plan printed, nothing written:"
sed 's/^/      /' "$DRILL_DIR/al-dry.log"
inst_admin "$I" audit accept-loss --first-broken-id $((LOST + 1)) "${common[@]}" --anchor ./anchor-before-loss.json --confirm \
    >"$DRILL_DIR/al.log" 2>&1 || { cat "$DRILL_DIR/al.log" >&2; fail "accept-loss --confirm failed"; }
grep -q "Accepted: seal #1" "$DRILL_DIR/al.log" || { cat "$DRILL_DIR/al.log" >&2; fail "accept-loss did not report the seal"; }
ok "$(grep -m1 'Accepted:' "$DRILL_DIR/al.log")"
offline 4

step "4. restart: online not_proven, then sealed (never valid)"
srv_start "$I" "$P"
login_admin "$I" "$P"
wait_status sealed 60
cli "$I" "$P" audit verify >"$DRILL_DIR/cli-verify.log" 2>&1 && fail "keyorix audit verify exited 0 on a sealed chain"
ok "keyorix audit verify: $(head -1 "$DRILL_DIR/cli-verify.log") (non-zero exit)"
srv_stop "$I"
offline 4

step "5. rotate-kek: the seal is carried over, a fresh checkpoint is written"
NEW_PW="drill-rotated-$(rand_hex 16)"
out="$(env KEYORIX_NEW_MASTER_PASSWORD="$NEW_PW" bash -c 'cd "$1" && shift && exec "$@"' _ "$d" \
    env KEYORIX_CONFIG_PATH=./keyorix.yaml ${PG_PASS:+KEYORIX_DB_PASSWORD="$PG_PASS"} \
    "$DRILL_SERVER_BIN" admin encryption rotate-kek --confirm --config ./keyorix.yaml 2>&1)" \
    || { echo "$out" >&2; fail "rotate-kek failed"; }
grep -q 'KEK rotation complete' <<<"$out" || { echo "$out" >&2; fail "rotate-kek did not report completion"; }
ok "rotate-kek complete"
export KEYORIX_MASTER_PASSWORD="$NEW_PW"
rm -f "$d/ckpt.key"
inst_admin "$I" audit export-checkpoint-key --output ./ckpt.key >/dev/null || fail "export-checkpoint-key (new key) failed"
offline 4
srv_start "$I" "$P"
login_admin "$I" "$P"
cli "$I" "$P" audit checkpoint >/dev/null || fail "audit checkpoint after rotate-kek failed"
wait_status sealed 60
srv_stop "$I"
offline 4

drill_end "ACCEPT-LOSS DRILL"
