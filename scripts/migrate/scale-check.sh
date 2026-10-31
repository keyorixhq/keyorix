#!/usr/bin/env bash
# scripts/migrate/scale-check.sh -- peak memory and wall time of backup, restore, the
# SQLite <-> PostgreSQL move and verify-audit on large data sets (SCALE-OPS-1).
#
# sqlite-to-pg-check.sh proves the move is CORRECT on a realistic instance with tens of
# thousands of rows. This script asks whether it still works, and what it costs, when
# the tables are large. For each size factor it
#
#   1. builds a SQLite instance (admin init / encryption init / migrate) and fills it in
#      bulk with scripts/migrate/scalegen: projects, users, secrets with versions,
#      shares, secret access-log rows and a chained audit log;
#   2. measures, each as its own process, peak RSS and wall time of
#        verify-audit            on the SQLite source
#        backup                  SQLite source
#        restore                 into an empty SQLite target        (SQLite -> SQLite)
#        verify-audit            on that target
#        restore                 into an empty PostgreSQL database  (SQLite -> PostgreSQL)
#        verify-audit            on the PostgreSQL target
#        backup                  PostgreSQL target
#        restore                 into an empty SQLite target        (PostgreSQL -> SQLite)
#        verify-audit            on that target
#   3. compares every table (row count + checksum, scripts/migrate/migratecheck
#      table-sums) between the source and each target, so a fast run that lost rows fails;
#   4. prints a table of rows against RSS and time.
#
# There is no separate "migrate" tool: moving between backends is `admin backup` on one
# backend and `admin restore` into a config that points at an EMPTY database of the other
# (docs/SELF_HOSTING.md). The legs above are exactly those commands.
#
# SCALE_MODE=kill (or all) also runs scale-kill-check.sh: the same restore and backup killed midway
# with SIGTERM and SIGKILL, and the documented recovery.
#
# A restore refuses an archive whose table (the audit log first) is larger than --max-entry-bytes
# (default 1 GiB uncompressed) or whose total is larger than --max-total-bytes (default 2 GiB). The
# harness raises both for the large sizes, as an operator with such an archive must.
#
# Usage (one EMPTY PostgreSQL database the script may DROP SCHEMA in; URL in a file so
# the password never travels on a command line):
#   MIGRATE_PG_DSN_FILE=a.txt [SCALE_FACTORS="1 4 16"] [SCALE_BASE_AUDIT=150000] \
#     [DRILL_SERVER_BIN=...] caffeinate -i scripts/migrate/scale-check.sh
#
#   SCALE_FACTORS      size multipliers, default "1 4 16"
#   SCALE_BASE_AUDIT   audit events at factor 1 (default 150000); the other tables scale
#                      with it: secrets /50 (x3 versions), access logs /2, users /300, shares /150
#   SCALE_MODE         measure (default) | kill | all
#   SCALE_OUT          results directory (default: <repo>/.scratch/scale)
#   DRILL_KEEP=1       keep the work area (the script always deletes the big files itself)
#
# Peak RSS comes from scripts/migrate/rssrun (wait4 rusage), not `/usr/bin/time -l`,
# which cannot run inside the macOS sandbox and differs on Linux.
set -euo pipefail
# shellcheck source=../drills/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/../drills/lib.sh"

: "${MIGRATE_PG_DSN_FILE:?set MIGRATE_PG_DSN_FILE to a file holding the URL of an EMPTY PostgreSQL database}"
SCALE_FACTORS="${SCALE_FACTORS:-1 4 16}"
SCALE_BASE_AUDIT="${SCALE_BASE_AUDIT:-150000}"
SCALE_MODE="${SCALE_MODE:-measure}"
SCALE_OUT="${SCALE_OUT:-$DRILL_REPO_ROOT/.scratch/scale}"
mkdir -p "$SCALE_OUT"
RESULTS="$SCALE_OUT/results.tsv"

# shellcheck disable=SC2034 # read by scripts/drills/lib.sh
DRILL_BACKEND=sqlite
# this script never calls the CLI; lib.sh wants a path that is executable
if [ -z "${DRILL_CLI_BIN:-}" ] && [ -n "${DRILL_SERVER_BIN:-}" ]; then DRILL_CLI_BIN="$DRILL_SERVER_BIN"; fi
drill_begin scale-check
# shellcheck source=scale-lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/scale-lib.sh"
build_scale_tools

# meas <size> <rows> <leg> <inst> <admin args...>: run `keyorix-server admin <args>` in the instance
# directory under rssrun and append one line to results.tsv. Sets M_EXIT and M_LOG.
meas() {
    local size="$1" rows="$2" leg="$3" name="$4"; shift 4
    local tag stats
    tag="$(printf '%s' "$leg" | tr -c 'A-Za-z0-9' '_')"
    stats="$DRILL_DIR/$name/$tag.stats"
    run_admin "$name" "$DRILL_DIR/$name/$tag.log" "$stats" -- "$@"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$size" "$rows" "$leg" "$(jq -r .wall_s "$stats")" \
        "$(jq -r '.maxrss_kb/1024|floor' "$stats")" "$M_EXIT" >>"$RESULTS"
    echo "    $leg: $(jq -r '"\(.wall_s)s, peak RSS \(.maxrss_kb/1024|floor) MB, exit \(.exit)"' "$stats")"
}

run_size() {
    local f="$1" src="src$1" ba="$SCALE_BASE_AUDIT"
    step "size ${f}x: $((ba * f)) audit events, $((ba * f / 50)) secrets x3 versions, $((ba * f / 2)) access-log rows, $((ba * f / 300)) users, $((ba * f / 150)) shares"
    seed_source "$src" "$((ba * f))" "$((ba * f / 50))" "$((ba * f / 2))" "$((ba * f / 300))" "$((ba * f / 150))"
    local amax="$SRC_AUDIT_MAX" rows="$SRC_ROWS" sums="$DRILL_DIR/$src.sums"

    meas "$f" "$rows" "verify-audit sqlite source" "$src" verify-audit; need_ok "verify-audit on the source"
    meas "$f" "$rows" "backup sqlite" "$src" backup --output ./backup.tar.gz; need_ok "backup"
    local arc="$DRILL_DIR/$src/backup.tar.gz" bytes
    bytes="$(wc -c <"$arc" | tr -d ' ')"
    ok "archive $bytes bytes"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$rows" "archive bytes" "-" "$bytes" "-" >>"$RESULTS"

    # SQLite -> SQLite
    on_sqlite; target "tgt-sq$f" sqlite "$src"
    meas "$f" "$rows" "restore sqlite->sqlite" "tgt-sq$f" restore --input "$arc" "${RESTORE_CAPS[@]}"; need_ok "restore into SQLite"
    meas "$f" "$rows" "verify-audit sqlite target" "tgt-sq$f" verify-audit; need_ok "verify-audit on the SQLite target"
    compare "$sums" "tgt-sq$f" "$amax"
    drop_big "tgt-sq$f"

    # SQLite -> PostgreSQL
    target "tgt-pg$f" postgres "$src"; on_pg
    mc "tgt-pg$f" reset-pg >/dev/null || fail "reset-pg"
    meas "$f" "$rows" "restore sqlite->postgres" "tgt-pg$f" restore --input "$arc" "${RESTORE_CAPS[@]}"; need_ok "restore into PostgreSQL"
    meas "$f" "$rows" "verify-audit postgres target" "tgt-pg$f" verify-audit; need_ok "verify-audit on PostgreSQL"
    compare "$sums" "tgt-pg$f" "$amax"
    rm -f "$arc"

    # PostgreSQL -> SQLite: back up the PostgreSQL instance just restored, restore into an empty SQLite
    meas "$f" "$rows" "backup postgres" "tgt-pg$f" backup --output ./backup-pg.tar.gz; need_ok "backup of PostgreSQL"
    local arcpg="$DRILL_DIR/tgt-pg$f/backup-pg.tar.gz"
    on_sqlite; target "tgt-pq$f" sqlite "$src"
    meas "$f" "$rows" "restore postgres->sqlite" "tgt-pq$f" restore --input "$arcpg" "${RESTORE_CAPS[@]}"; need_ok "restore of the PostgreSQL archive into SQLite"
    meas "$f" "$rows" "verify-audit sqlite target (from postgres)" "tgt-pq$f" verify-audit; need_ok "verify-audit on the SQLite target"
    compare "$sums" "tgt-pq$f" "$amax"
    drop_big "tgt-pq$f"; rm -f "$arcpg"
    on_pg; mc "tgt-pg$f" reset-pg >/dev/null || true
    on_sqlite; drop_big "$src"
}

if [ "$SCALE_MODE" = measure ] || [ "$SCALE_MODE" = all ]; then
    printf 'size\trows\tleg\twall_s\tmaxrss_mb\texit\n' >"$RESULTS"
    for f in $SCALE_FACTORS; do run_size "$f"; done
    step "results ($RESULTS)"
    column -t -s "$(printf '\t')" "$RESULTS"
fi

if [ "$SCALE_MODE" = kill ] || [ "$SCALE_MODE" = all ]; then
    step "failure behaviour: scripts/migrate/scale-kill-check.sh"
    "$(dirname "${BASH_SOURCE[0]}")/scale-kill-check.sh"
fi

drill_end "scale-check"
