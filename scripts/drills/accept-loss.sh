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
#      still read SEALED under the new key (offline with the newly exported key);
#   6. (SQLite, AUDIT-SEAL-TAILS-1 finding 2) the database metadata is rolled back below the host
#      witness and more rows are lost: the plan counts and names the witness, refuses until its
#      missing head is named, and the confirmed acceptance lowers it only as the plan said;
#   7. (AUDIT-SEAL-TAILS-1 finding 1) the seal record is garbled and rotate-kek runs again: the
#      key change completes but the audit transition stops with "cannot be trusted" and signs
#      no high-water mark or checkpoint.
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

# db_query <sql>: one value from the instance database (no headers).
db_query() {
    if [ "$DRILL_BACKEND" = "postgres" ]; then
        PGPASSWORD="$PG_PASS" psql "postgres://$PG_USER@$PG_HOST:$PG_PORT/$PG_DB?sslmode=disable" -v ON_ERROR_STOP=1 -At -c "$1"
    else
        sqlite3 "$d/keyorix.db" "$1"
    fi
}

# meta <key>: a system_metadata value (compare only with another meta: the sqlite3 CLI prints
# control characters such as the high-water separator as ^_).
meta() { db_query "SELECT value FROM system_metadata WHERE \"key\" = '$1'"; }

# sqlite_meta_hex <key> / file_hex <file>: the exact bytes, upper-case hex (SQLite only).
sqlite_meta_hex() { sqlite3 "$d/keyorix.db" "SELECT hex(value) FROM system_metadata WHERE key = '$1'"; }
file_hex() { od -An -tx1 "$1" | tr -d ' \n' | tr 'a-f' 'A-F'; }

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

step "6. witness above the database (finding 2)"
if [ "$DRILL_BACKEND" = "postgres" ]; then
    ok "skipped: PostgreSQL installs have no host witness file"
else
    W="$d/.audit-highwater-witness"
    HW0="$(sqlite_meta_hex audit_checkpoint_highwater)"
    ST0="$(sqlite_meta_hex audit_verification_state)"
    CP0="$(db_query "SELECT MAX(id) FROM audit_checkpoints")"
    srv_start "$I" "$P"
    for _ in 1 2 3 4 5 6; do login_admin "$I" "$P"; done
    cli "$I" "$P" audit checkpoint >/dev/null || fail "audit checkpoint failed"
    srv_stop "$I"
    [ -f "$W" ] || fail "no witness file at $W"
    WIT="$(cat "$W")"
    # v2 layout (under a seal): v2 US n US digest US events US head_id US ...
    WHEAD="$(printf '%s' "$WIT" | tr '\037' '\n' | sed -n 5p)"
    [ -n "$WHEAD" ] && [ "$WHEAD" -gt 0 ] || fail "cannot read the witness head from $W"
    ok "witness certifies through #$WHEAD"
    # An in-database rollback of the metadata to before that checkpoint, then the two newest
    # rows and one more row are lost: only the witness still certifies the tail.
    db_exec "DELETE FROM audit_checkpoints WHERE id > $CP0" >/dev/null
    sqlite3 "$d/keyorix.db" "UPDATE system_metadata SET value = CAST(X'$HW0' AS TEXT) WHERE key = 'audit_checkpoint_highwater'"
    sqlite3 "$d/keyorix.db" "UPDATE system_metadata SET value = CAST(X'$ST0' AS TEXT) WHERE key = 'audit_verification_state'"
    db_exec "DELETE FROM audit_events WHERE id >= $((WHEAD - 1))" >/dev/null
    GAP=$((WHEAD - 4))
    db_exec "DELETE FROM audit_events WHERE id = $GAP" >/dev/null
    common2=(--operator drill-oncall --reason "DRILL-2: row $GAP and the tail lost" --evidence-sha256 "$EVIDENCE")
    if inst_admin "$I" audit accept-loss --first-broken-id $((GAP + 1)) "${common2[@]}" --confirm >"$DRILL_DIR/al2-unnamed.log" 2>&1; then
        fail "accept-loss sealed a gap while the witness's head is gone and not named"
    fi
    grep -q "witness" "$DRILL_DIR/al2-unnamed.log" || { cat "$DRILL_DIR/al2-unnamed.log" >&2; fail "unnamed witness head: unexpected refusal"; }
    [ "$(cat "$W")" = "$WIT" ] || fail "the witness changed on a refused acceptance"
    ok "witness head not named: refused, witness unchanged"
    if inst_admin "$I" audit accept-loss --first-broken-id $((GAP + 1)) --first-broken-id "$WHEAD" "${common2[@]}" >"$DRILL_DIR/al2-dry.log" 2>&1; then
        fail "accept-loss wrote without --confirm"
    fi
    grep -q "host witness file: certifies" "$DRILL_DIR/al2-dry.log" || { cat "$DRILL_DIR/al2-dry.log" >&2; fail "the plan does not name the witness"; }
    grep -q "LOWERS" "$DRILL_DIR/al2-dry.log" || { cat "$DRILL_DIR/al2-dry.log" >&2; fail "the plan does not say the witness is lowered"; }
    [ "$(cat "$W")" = "$WIT" ] || fail "the witness changed on a dry run"
    ok "plan names the witness: $(grep -m1 'host witness file' "$DRILL_DIR/al2-dry.log" | sed 's/^ *//' | cut -c1-140)"
    inst_admin "$I" audit accept-loss --first-broken-id $((GAP + 1)) --first-broken-id "$WHEAD" "${common2[@]}" --confirm \
        >"$DRILL_DIR/al2.log" 2>&1 || { cat "$DRILL_DIR/al2.log" >&2; fail "accept-loss --confirm (seal #2) failed"; }
    grep -q "Accepted: seal #2" "$DRILL_DIR/al2.log" || { cat "$DRILL_DIR/al2.log" >&2; fail "accept-loss did not report seal #2"; }
    [ "$(file_hex "$W")" = "$(sqlite_meta_hex audit_checkpoint_highwater)" ] || fail "the witness is not the new high-water mark"
    ok "sealed #2; the witness was lowered to the new mark, as the confirmed plan said"
    offline 4
fi

step "7. garbled seal record during rotate-kek (finding 1)"
db_exec "UPDATE system_metadata SET value = 'garbage' WHERE \"key\" = 'audit_seals'" >/dev/null
HW1="$(meta audit_checkpoint_highwater)"
CPN="$(db_query "SELECT COUNT(*) FROM audit_checkpoints")"
NEW_PW2="drill-rotated2-$(rand_hex 16)"
out="$(env KEYORIX_NEW_MASTER_PASSWORD="$NEW_PW2" bash -c 'cd "$1" && shift && exec "$@"' _ "$d" \
    env KEYORIX_CONFIG_PATH=./keyorix.yaml ${PG_PASS:+KEYORIX_DB_PASSWORD="$PG_PASS"} \
    "$DRILL_SERVER_BIN" admin encryption rotate-kek --confirm --config ./keyorix.yaml 2>&1)" \
    || { echo "$out" >&2; fail "rotate-kek failed"; }
grep -q 'KEK rotation complete' <<<"$out" || { echo "$out" >&2; fail "rotate-kek did not report completion"; }
grep -q 'not carried over yet: .*seal record cannot be trusted.*not completed' <<<"$out" || { echo "$out" >&2; fail "the audit transition did not stop on the untrusted seal record"; }
[ "$(meta audit_checkpoint_highwater)" = "$HW1" ] || fail "the high-water mark was re-signed against an untrusted seal list"
[ "$(db_query "SELECT COUNT(*) FROM audit_checkpoints")" = "$CPN" ] || fail "a checkpoint was written against an untrusted seal list"
ok "key change complete, audit transition stopped: $(grep -m1 'not carried over yet' <<<"$out" | cut -c1-160)"
export KEYORIX_MASTER_PASSWORD="$NEW_PW2"
rm -f "$d/ckpt.key"
inst_admin "$I" audit export-checkpoint-key --output ./ckpt.key >/dev/null || fail "export-checkpoint-key (third key) failed"
offline 1
srv_start "$I" "$P"
login_admin "$I" "$P"
srv_stop "$I"
grep -q 'audit key transition not completed at startup: .*cannot be trusted' "$d/server.log" || fail "the server start did not refuse the transition"
[ "$(meta audit_checkpoint_highwater)" = "$HW1" ] || fail "the server start re-signed the high-water mark"
ok "server start: transition still refused, nothing re-signed"

drill_end "ACCEPT-LOSS DRILL"
