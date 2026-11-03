#!/usr/bin/env bash
# scripts/migrate/scale-kill-check.sh -- failure behaviour of backup and restore at scale
# (SCALE-OPS-1, item 4). Kills the real `keyorix-server admin backup` / `admin restore`
# midway, with SIGTERM and with SIGKILL, on a large data set, and checks that
#
#   * what is left behind is what docs/operator/restore-failure-modes.md says,
#   * the target never looks valid: no database, no installed key files, no partial rows,
#   * the documented way forward works on the big data set (re-run; or
#     `admin restore --recover` when a journal exists) and the result equals the source
#     table by table, with a VALID audit chain.
#
# Signals are sent by scripts/migrate/rssrun (to the command's own PID, when a progress
# line appears in its output or after a delay), never with the shared `kill`.
#
# Usage:
#   MIGRATE_PG_DSN_FILE=a.txt [SCALE_KILL_FACTOR=4] [SCALE_BASE_AUDIT=150000] \
#     [DRILL_SERVER_BIN=...] caffeinate -i scripts/migrate/scale-kill-check.sh
#   SCALE_KILL_AFTER_MS   delay after the "Loading data" line before the signal (default 3000)
#   SCALE_KILL_BACKUP_MS  delay after a backup starts before the signal (default 12000, must land after the hashing pass)
set -euo pipefail
# shellcheck source=../drills/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../drills/lib.sh"
# shellcheck source=scale-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/scale-lib.sh"

: "${MIGRATE_PG_DSN_FILE:?set MIGRATE_PG_DSN_FILE to a file holding the URL of an EMPTY PostgreSQL database}"
F="${SCALE_KILL_FACTOR:-4}"
BA="${SCALE_BASE_AUDIT:-150000}"
AFTER_MS="${SCALE_KILL_AFTER_MS:-3000}"
BACKUP_MS="${SCALE_KILL_BACKUP_MS:-12000}"

# shellcheck disable=SC2034 # read by scripts/drills/lib.sh
DRILL_BACKEND=sqlite
if [ -z "${DRILL_CLI_BIN:-}" ] && [ -n "${DRILL_SERVER_BIN:-}" ]; then DRILL_CLI_BIN="$DRILL_SERVER_BIN"; fi
drill_begin scale-kill-check
build_scale_tools

has_journal() { [ -e "$DRILL_DIR/$1/.keyorix-restore-journal.json" ] || [ -e "$DRILL_DIR/$1/keys/.keyorix-restore-journal.json" ]; }

# state <inst>: one line describing what is on disk for an instance.
state() {
    local d="$DRILL_DIR/$1" db="no" keys="" j="no" staged=0 f
    [ -e "$d/keyorix.db" ] && db="YES"
    for f in "$d"/keys/*; do
        [ -e "$f" ] || continue
        case "$f" in
            *restoring*) staged=$((staged + 1)) ;;
            *) keys="$keys$(basename "$f") " ;;
        esac
    done
    for f in "$d"/keyorix.db.restoring-*; do [ -e "$f" ] && staged=$((staged + 1)); done
    if has_journal "$1"; then j="YES"; fi
    echo "database file: $db; key-dir files: [${keys:-none}]; journal: $j; staged leftovers: $staged"
}
installed_keys() { # <inst>: number of installed key files (dek.key / kek.salt)
    local d="$DRILL_DIR/$1" n=0 f
    for f in "$d/keys/dek.key" "$d/keys/kek.salt"; do [ -e "$f" ] && n=$((n + 1)); done
    echo "$n"
}

step "source: ${F}x data set ($((BA * F)) audit events)"
seed_source src "$((BA * F))" "$((BA / 50 * F))" "$((BA / 2 * F))" "$((BA / 300 * F))" "$((BA / 150 * F))"
SUMS="$DRILL_DIR/src.sums"
AMAX="$SRC_AUDIT_MAX"
run_admin src "$DRILL_DIR/src/backup.log" "$DRILL_DIR/src/backup.stats" -- backup --output ./backup.tar.gz
need_ok "backup of the source"
ARC="$DRILL_DIR/src/backup.tar.gz"
ok "archive $(wc -c <"$ARC" | tr -d ' ') bytes"

# ---------------------------------------------------------------------------------------------
# restore killed while it loads, SQLite target
# ---------------------------------------------------------------------------------------------
for SIG in TERM KILL; do
    T="tgt-sq-$SIG"
    step "SIG$SIG during \`admin restore\` into SQLite (while the staged database is loading)"
    on_sqlite; target "$T" sqlite src
    run_admin "$T" "$DRILL_DIR/$T/kill.log" "$DRILL_DIR/$T/kill.stats" --kill "$SIG" --when "Loading data into the staged database" \
        --after-ms "$AFTER_MS" -- restore --input "$ARC" "${RESTORE_CAPS[@]}"
    [ "$M_EXIT" = 99 ] || { tail -5 "$M_LOG" >&2; fail "the restore ended (exit $M_EXIT) before SIG$SIG could be sent; use a larger SCALE_KILL_FACTOR"; }
    ok "restore ended by SIG$SIG after $(jq -r '.wall_s' "$DRILL_DIR/$T/kill.stats")s"
    echo "    left behind: $(state "$T")"
    [ ! -e "$DRILL_DIR/$T/keyorix.db" ] || fail "SIG$SIG: a database file exists at the live path after an interrupted restore"
    [ "$(installed_keys "$T")" = 0 ] || fail "SIG$SIG: key files were installed by an interrupted restore"
    ! has_journal "$T" || fail "SIG$SIG: a journal exists although the staged database was not complete"
    ok "the target does not look valid: no database, no installed key files, no journal"
    run_admin "$T" "$DRILL_DIR/$T/verify.log" "$DRILL_DIR/$T/verify.stats" -- verify-audit
    [ "$M_EXIT" != 0 ] || fail "verify-audit passed on a target whose restore was killed"
    ok "verify-audit on the half-restored target does not pass (exit $M_EXIT)"
    step "documented recovery: re-run the restore (it removes the staged leftovers first)"
    run_admin "$T" "$DRILL_DIR/$T/rerun.log" "$DRILL_DIR/$T/rerun.stats" -- restore --input "$ARC" "${RESTORE_CAPS[@]}"
    need_ok "re-run of the restore after SIG$SIG"
    if grep -q 'Removed a leftover staged file' "$DRILL_DIR/$T/rerun.log"; then ok "re-run removed the leftover staged files"; else ok "re-run found no leftovers to remove"; fi
    grep -q 'VALID' "$DRILL_DIR/$T/rerun.log" || fail "re-run did not report verify-audit VALID"
    compare "$SUMS" "$T" "$AMAX"
    [ "$(state "$T" | sed -E 's/.*staged leftovers: //')" = 0 ] || fail "staged leftovers remain after the re-run"
    drop_big "$T"
done

# ---------------------------------------------------------------------------------------------
# restore killed while it loads, PostgreSQL target (one transaction)
# ---------------------------------------------------------------------------------------------
for SIG in TERM KILL; do
    T="tgt-pg-$SIG"
    step "SIG$SIG during \`admin restore\` into PostgreSQL (inside the load transaction)"
    target "$T" postgres src; on_pg
    mc "$T" reset-pg >/dev/null || fail "reset-pg"
    run_admin "$T" "$DRILL_DIR/$T/kill.log" "$DRILL_DIR/$T/kill.stats" --kill "$SIG" --when "Loading data into the restored database in one transaction" \
        --after-ms "$AFTER_MS" -- restore --input "$ARC" "${RESTORE_CAPS[@]}"
    [ "$M_EXIT" = 99 ] || { tail -5 "$M_LOG" >&2; fail "the restore ended (exit $M_EXIT) before SIG$SIG could be sent; use a larger SCALE_KILL_FACTOR"; }
    ok "restore ended by SIG$SIG after $(jq -r '.wall_s' "$DRILL_DIR/$T/kill.stats")s"
    echo "    left behind: $(state "$T")"
    [ "$(installed_keys "$T")" = 0 ] || fail "SIG$SIG: key files were installed before the load committed"
    # the server side rolls the abandoned transaction back once it notices the dead connection
    AE=""
    for _ in $(seq 1 60); do
        AE="$(mc "$T" count --key audit_events 2>/dev/null || echo none)"
        [ "$AE" = 0 ] && break
        sleep 1
    done
    [ "$AE" = 0 ] || fail "SIG$SIG: audit_events has '$AE' rows after the killed load (expected 0: the load is one transaction)"
    ok "audit_events holds 0 rows: the load transaction rolled back, nothing partial is visible"
    if has_journal "$T"; then
        run_admin "$T" "$DRILL_DIR/$T/plain.log" "$DRILL_DIR/$T/plain.stats" -- restore --input "$ARC" "${RESTORE_CAPS[@]}"
        [ "$M_EXIT" != 0 ] || fail "a plain re-run of the restore was accepted while the journal exists"
        grep -q 'interrupted .admin restore.' "$M_LOG" || { cat "$M_LOG" >&2; fail "the refusal does not name the interrupted restore"; }
        ok "a plain re-run is refused and names the interrupted restore"
        step "documented recovery: admin restore --recover (rolls back, the load never committed)"
        run_admin "$T" "$DRILL_DIR/$T/recover.log" "$DRILL_DIR/$T/recover.stats" -- restore --recover
        need_ok "restore --recover after SIG$SIG"
        grep -q 'Rolled back' "$DRILL_DIR/$T/recover.log" || { cat "$DRILL_DIR/$T/recover.log" >&2; fail "--recover did not report a rollback"; }
        ok "recover: $(grep 'Rolled' "$DRILL_DIR/$T/recover.log" | head -1)"
        ! has_journal "$T" || fail "the journal remains after --recover"
        echo "    after recovery: $(state "$T")"
    else
        ok "no journal was written at this point; re-run directly"
    fi
    # the killed restore's migrations had already created the (empty) schema, so a plain re-run is refused
    # as a populated target; --overwrite-existing is what the refusal message offers, and here it replaces
    # empty tables only
    run_admin "$T" "$DRILL_DIR/$T/plain2.log" "$DRILL_DIR/$T/plain2.stats" -- restore --input "$ARC" "${RESTORE_CAPS[@]}"
    [ "$M_EXIT" != 0 ] || fail "a plain restore into the schema left by the killed restore was accepted"
    grep -q 'overwrite-existing' "$M_LOG" || { cat "$M_LOG" >&2; fail "the refusal does not name --overwrite-existing"; }
    ok "after recovery a plain re-run is refused (the empty schema is still there) and names --overwrite-existing"
    run_admin "$T" "$DRILL_DIR/$T/rerun.log" "$DRILL_DIR/$T/rerun.stats" -- restore --input "$ARC" --overwrite-existing "${RESTORE_CAPS[@]}"
    need_ok "restore --overwrite-existing after recovery (SIG$SIG)"
    grep -q 'VALID' "$DRILL_DIR/$T/rerun.log" || fail "restore did not report verify-audit VALID"
    compare "$SUMS" "$T" "$AMAX"
done
on_pg; mc tgt-pg-KILL reset-pg >/dev/null || true; mc tgt-pg-TERM reset-pg >/dev/null || true

# ---------------------------------------------------------------------------------------------
# backup killed while it writes the archive
# ---------------------------------------------------------------------------------------------
for SIG in TERM KILL; do
    step "SIG$SIG during \`admin backup\` of the SQLite source (${BACKUP_MS} ms after it started)"
    on_sqlite
    run_admin src "$DRILL_DIR/src/bk-$SIG.log" "$DRILL_DIR/src/bk-$SIG.stats" --kill "$SIG" --after-ms "$BACKUP_MS" -- backup --output "./partial-$SIG.tar.gz"
    [ "$M_EXIT" = 99 ] || fail "the backup ended (exit $M_EXIT) before SIG$SIG could be sent; use a larger SCALE_KILL_FACTOR or a shorter SCALE_KILL_BACKUP_MS"
    P="$DRILL_DIR/src/partial-$SIG.tar.gz"
    if [ -e "$P" ]; then echo "    left behind: a partial archive of $(wc -c <"$P" | tr -d ' ') bytes"; else echo "    left behind: no archive file"; fi
    if [ -e "$P" ]; then
        T="tgt-bk-$SIG"
        target "$T" sqlite src
        run_admin "$T" "$DRILL_DIR/$T/restore.log" "$DRILL_DIR/$T/restore.stats" -- restore --input "$P"
        [ "$M_EXIT" != 0 ] || fail "a restore from a partial archive was accepted"
        [ ! -e "$DRILL_DIR/$T/keyorix.db" ] && [ "$(installed_keys "$T")" = 0 ] || fail "a restore from a partial archive changed the target"
        ok "a restore from the partial archive is refused (exit $M_EXIT) and changes nothing"
        run_admin src "$DRILL_DIR/src/again.log" "$DRILL_DIR/src/again.stats" -- backup --output "./partial-$SIG.tar.gz"
        [ "$M_EXIT" != 0 ] || fail "a backup over the partial archive path was accepted"
        ok "a backup to the same path is refused (it never overwrites): delete the partial file and re-run"
        rm -f "$P"
    fi
    run_admin src "$DRILL_DIR/src/retry-$SIG.log" "$DRILL_DIR/src/retry-$SIG.stats" -- backup --output "./retry-$SIG.tar.gz"
    need_ok "backup after SIG$SIG"
    ok "a fresh backup after SIG$SIG succeeds ($(wc -c <"$DRILL_DIR/src/retry-$SIG.tar.gz" | tr -d ' ') bytes)"
    rm -f "$DRILL_DIR/src/retry-$SIG.tar.gz"
done

drill_end "scale-kill-check"
