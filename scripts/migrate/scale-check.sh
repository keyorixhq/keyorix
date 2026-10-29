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
# SCALE_MODE=kill runs the failure behaviour instead (see the kill section below).
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

DRILL_BACKEND=sqlite
# this script never calls the CLI; lib.sh wants a path that is executable
if [ -z "${DRILL_CLI_BIN:-}" ] && [ -n "${DRILL_SERVER_BIN:-}" ]; then DRILL_CLI_BIN="$DRILL_SERVER_BIN"; fi
drill_begin scale-check
BIN="$DRILL_DIR/bin"
(cd "$DRILL_REPO_ROOT" && GOWORK=off go build -o "$BIN/migratecheck" scripts/migrate/migratecheck/main.go \
    && GOWORK=off go build -o "$BIN/scalegen" scripts/migrate/scalegen/main.go \
    && GOWORK=off go build -o "$BIN/rssrun" scripts/migrate/rssrun/main.go) || fail "tool build failed"
MC="$BIN/migratecheck"
SG="$BIN/scalegen"
RSSRUN="$BIN/rssrun"

on_sqlite() { DRILL_BACKEND=sqlite; }
on_pg() { DRILL_BACKEND=postgres; pg_parse "$MIGRATE_PG_DSN_FILE"; }

# mc <inst> <migratecheck args...>
mc() {
    local name="$1"; shift
    inst_run "$name" env KEYORIX_CONFIG_PATH=./keyorix.yaml "$MC" "$1" --config ./keyorix.yaml "${@:2}"
}

# target <name> <sqlite|postgres>: an instance that is the SOURCE's config, certs and secrets
# (what an operator copies to the new host) and NO keys, on an empty database.
target() {
    local name="$1" kind="$2" src="$3" d="$DRILL_DIR/$1"
    mkdir -p "$d/home"
    cp "$DRILL_DIR/$src/keyorix.yaml" "$d/keyorix.yaml"
    cp -R "$DRILL_DIR/$src/certs" "$d/certs"
    cp -R "$DRILL_DIR/$src/secrets" "$d/secrets"
    if [ "$kind" = postgres ]; then
        pg_parse "$MIGRATE_PG_DSN_FILE"
        sed -i.bak -E \
            -e 's/^  type: sqlite.*/  type: postgres/' \
            -e "s|^    path: \"keyorix.db\"|    host: \"$PG_HOST\"\n    port: \"$PG_PORT\"\n    name: \"$PG_DB\"\n    user: \"$PG_USER\"\n    ssl_mode: disable|" \
            "$d/keyorix.yaml"
        rm -f "$d/keyorix.yaml.bak"
        grep -q 'type: postgres' "$d/keyorix.yaml" || fail "target: config edit did not take ($name)"
    fi
}

# meas <size> <rows> <leg> <inst> <admin args...>: run `keyorix-server admin <args>` in the
# instance directory under rssrun and append one line to results.tsv. Sets M_EXIT.
meas() {
    local size="$1" rows="$2" leg="$3" name="$4"; shift 4
    local d="$DRILL_DIR/$name" tag stats log
    tag="$(printf '%s' "$leg" | tr -c 'A-Za-z0-9' '_')"
    stats="$d/$tag.stats"
    log="$d/$tag.log"
    M_LOG="$log"
    (
        cd "$d"
        if [ "$DRILL_BACKEND" = "postgres" ]; then export KEYORIX_DB_PASSWORD="$PG_PASS"; fi
        export KEYORIX_CONFIG_PATH=./keyorix.yaml
        "$RSSRUN" --stats "$stats" --log "$log" -- "$DRILL_SERVER_BIN" admin "$@" --config ./keyorix.yaml
    ) || true
    [ -s "$stats" ] || fail "$leg: no result recorded"
    M_EXIT="$(jq -r .exit "$stats")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$size" "$rows" "$leg" "$(jq -r .wall_s "$stats")" \
        "$(jq -r '.maxrss_kb/1024|floor' "$stats")" "$M_EXIT" >>"$RESULTS"
    echo "    $leg: $(jq -r '"\(.wall_s)s, peak RSS \(.maxrss_kb/1024|floor) MB, exit \(.exit)"' "$stats")"
}

# need_ok <what>: the last meas must have exited 0
need_ok() { [ "$M_EXIT" = 0 ] || { tail -20 "$M_LOG" >&2 || true; fail "$1 failed (exit $M_EXIT)"; }; }

# compare <src-sums> <inst> <audit-max>: every table of <inst> equals the source's sums.
compare() {
    local sums="$1" inst="$2" amax="$3" mismatch
    mc "$inst" table-sums --audit-max-id "$amax" >"$DRILL_DIR/$inst.sums" || fail "table-sums on $inst"
    mismatch="$(jq -n -r --slurpfile s "$sums" --slurpfile d "$DRILL_DIR/$inst.sums" '
        ($s | map(select(.table != "__audit_max_id") | {(.table): .}) | add) as $S
      | ($d | map(select(.table != "__audit_max_id") | {(.table): .}) | add) as $D
      | $S | keys[]
      | select($S[.].count != ($D[.].count // -1) or $S[.].sha256 != ($D[.].sha256 // ""))
      | "\(.): source \($S[.].count) rows, target \(($D[.].count // -1)) rows"')"
    [ -z "$mismatch" ] || { echo "$mismatch" >&2; fail "tables differ between the source and $inst"; }
    ok "$inst: every table equal to the source (counts + checksums)"
}

# drop_big <inst>: remove the large files of an instance by name (the work area itself is
# removed by the drill cleanup, which a restricted sandbox may refuse; disk must not fill up).
drop_big() {
    local d="$DRILL_DIR/$1"
    rm -f "$d"/keyorix.db "$d"/keyorix.db-wal "$d"/keyorix.db-shm "$d"/*.tar.gz "$d"/keyorix.db.restoring-* 2>/dev/null || true
}

run_size() {
    local f="$1" src="src$1" ba="$SCALE_BASE_AUDIT"
    local audit=$((ba * f)) secrets=$((ba / 50 * f)) access=$((ba / 2 * f)) users=$((ba / 300 * f)) shares=$((ba / 150 * f))
    step "size ${f}x: ${audit} audit events, ${secrets} secrets x3 versions, ${access} access-log rows, ${users} users, ${shares} shares"
    on_sqlite
    inst_new "$src" "$(drill_port $((40 + f)))"
    inst_run "$src" "$SG" seed --config ./keyorix.yaml --audit "$audit" --secrets "$secrets" --versions 3 \
        --access-logs "$access" --users "$users" --shares "$shares" --projects 10 || fail "scalegen failed"
    mc "$src" table-sums >"$DRILL_DIR/$src.sums" || fail "table-sums on the source"
    local amax rows
    amax="$(jq -r 'select(.table=="__audit_max_id") | .count' "$DRILL_DIR/$src.sums")"
    rows="$(jq -s 'map(select(.table!="__audit_max_id") | .count) | add' "$DRILL_DIR/$src.sums")"
    ok "source: $rows rows in $(jq -s 'map(select(.table!="__audit_max_id" and .count>0)) | length' "$DRILL_DIR/$src.sums") non-empty tables, newest audit id $amax"

    meas "$f" "$rows" "verify-audit sqlite source" "$src" verify-audit; need_ok "verify-audit on the source"
    meas "$f" "$rows" "backup sqlite" "$src" backup --output ./backup.tar.gz; need_ok "backup"
    ok "archive $(wc -c <"$DRILL_DIR/$src/backup.tar.gz" | tr -d ' ') bytes"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$f" "$rows" "archive bytes" "-" "$(wc -c <"$DRILL_DIR/$src/backup.tar.gz" | tr -d ' ')" "-" >>"$RESULTS"
    local arc="$DRILL_DIR/$src/backup.tar.gz"

    # SQLite -> SQLite
    on_sqlite; target "tgt-sq$f" sqlite "$src"
    meas "$f" "$rows" "restore sqlite->sqlite" "tgt-sq$f" restore --input "$arc"; need_ok "restore into SQLite"
    meas "$f" "$rows" "verify-audit sqlite target" "tgt-sq$f" verify-audit; need_ok "verify-audit on the SQLite target"
    compare "$DRILL_DIR/$src.sums" "tgt-sq$f" "$amax"
    drop_big "tgt-sq$f"

    # SQLite -> PostgreSQL
    target "tgt-pg$f" postgres "$src"; on_pg
    mc "tgt-pg$f" reset-pg >/dev/null || fail "reset-pg"
    meas "$f" "$rows" "restore sqlite->postgres" "tgt-pg$f" restore --input "$arc"; need_ok "restore into PostgreSQL"
    meas "$f" "$rows" "verify-audit postgres target" "tgt-pg$f" verify-audit; need_ok "verify-audit on PostgreSQL"
    compare "$DRILL_DIR/$src.sums" "tgt-pg$f" "$amax"

    # PostgreSQL -> SQLite: back up the PostgreSQL instance just restored, restore into an empty SQLite
    meas "$f" "$rows" "backup postgres" "tgt-pg$f" backup --output ./backup-pg.tar.gz; need_ok "backup of PostgreSQL"
    local arcpg="$DRILL_DIR/tgt-pg$f/backup-pg.tar.gz"
    on_sqlite; target "tgt-pq$f" sqlite "$src"
    meas "$f" "$rows" "restore postgres->sqlite" "tgt-pq$f" restore --input "$arcpg"; need_ok "restore PostgreSQL archive into SQLite"
    meas "$f" "$rows" "verify-audit sqlite target (from postgres)" "tgt-pq$f" verify-audit; need_ok "verify-audit"
    compare "$DRILL_DIR/$src.sums" "tgt-pq$f" "$amax"
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

# kill section is appended below by the failure-behaviour change (item 4)

drill_end "scale-check"
