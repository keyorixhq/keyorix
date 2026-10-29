#!/usr/bin/env bash
# scripts/migrate/scale-lib.sh -- helpers shared by scale-check.sh and scale-kill-check.sh
# (SCALE-OPS-1). Sourced AFTER scripts/drills/lib.sh and after drill_begin; needs
# MIGRATE_PG_DSN_FILE. See scale-check.sh for what the legs measure.

# Restore refuses a table over 1 GiB uncompressed and an archive over 2 GiB unless told otherwise
# (docs/operator/backup-restore-scale.md); the large sizes need the limits raised.
# shellcheck disable=SC2034 # used by the scripts that source this file
RESTORE_CAPS=(--max-entry-bytes "${SCALE_MAX_ENTRY_BYTES:-17179869184}" --max-total-bytes "${SCALE_MAX_TOTAL_BYTES:-34359738368}")

# build_scale_tools: migratecheck (table sums, reset-pg), scalegen (bulk seed), rssrun (RSS + kill).
build_scale_tools() {
    local bin="$DRILL_DIR/bin"
    (cd "$DRILL_REPO_ROOT" && GOWORK=off go build -o "$bin/migratecheck" scripts/migrate/migratecheck/main.go \
        && GOWORK=off go build -o "$bin/scalegen" scripts/migrate/scalegen/main.go \
        && GOWORK=off go build -o "$bin/rssrun" scripts/migrate/rssrun/main.go) || fail "tool build failed"
    MC="$bin/migratecheck"
    SG="$bin/scalegen"
    RSSRUN="$bin/rssrun"
}

on_sqlite() { DRILL_BACKEND=sqlite; }
on_pg() { DRILL_BACKEND=postgres; pg_parse "$MIGRATE_PG_DSN_FILE"; }

# mc <inst> <migratecheck args...>
mc() {
    local name="$1"; shift
    inst_run "$name" env KEYORIX_CONFIG_PATH=./keyorix.yaml "$MC" "$1" --config ./keyorix.yaml "${@:2}"
}

# target <name> <sqlite|postgres> <source-inst>: an instance that is the SOURCE's config, certs
# and secrets (what an operator copies to the new host) and NO keys, on an empty database.
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

# seed_source <name> <audit> <secrets> <access> <users> <shares>: a fresh SQLite instance filled in
# bulk; leaves its table sums in $DRILL_DIR/<name>.sums and sets SRC_ROWS and SRC_AUDIT_MAX.
seed_source() {
    local src="$1" audit="$2" secrets="$3" access="$4" users="$5" shares="$6"
    on_sqlite
    inst_new "$src" "$(drill_port 40)"
    inst_run "$src" "$SG" seed --config ./keyorix.yaml --audit "$audit" --secrets "$secrets" --versions 3 \
        --access-logs "$access" --users "$users" --shares "$shares" --projects 10 || fail "scalegen failed"
    mc "$src" table-sums >"$DRILL_DIR/$src.sums" || fail "table-sums on the source"
    SRC_AUDIT_MAX="$(jq -r 'select(.table=="__audit_max_id") | .count' "$DRILL_DIR/$src.sums")"
    SRC_ROWS="$(jq -s 'map(select(.table!="__audit_max_id") | .count) | add' "$DRILL_DIR/$src.sums")"
    ok "source: $SRC_ROWS rows in $(jq -s 'map(select(.table!="__audit_max_id" and .count>0)) | length' "$DRILL_DIR/$src.sums") non-empty tables, newest audit id $SRC_AUDIT_MAX"
}

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

# run_admin <inst> <logfile> <stats> [rssrun options...] -- <admin args...>: `keyorix-server admin <args>`
# in the instance directory under rssrun. Sets M_EXIT (rssrun's record of the exit status: 99 = ended by
# an injected signal) and M_LOG.
run_admin() {
    local name="$1" log="$2" stats="$3"; shift 3
    local opts=()
    while [ "$1" != "--" ]; do opts+=("$1"); shift; done
    shift
    local d="$DRILL_DIR/$name"
    M_LOG="$log"
    rm -f "$stats"
    (
        cd "$d"
        if [ "$DRILL_BACKEND" = "postgres" ]; then export KEYORIX_DB_PASSWORD="$PG_PASS"; fi
        export KEYORIX_CONFIG_PATH=./keyorix.yaml
        "$RSSRUN" --stats "$stats" --log "$log" ${opts[@]+"${opts[@]}"} -- "$DRILL_SERVER_BIN" admin "$@" --config ./keyorix.yaml
    ) || true
    [ -s "$stats" ] || fail "admin $*: no result recorded"
    M_EXIT="$(jq -r .exit "$stats")"
}

# need_ok <what>: the last run must have exited 0
need_ok() { [ "$M_EXIT" = 0 ] || { tail -20 "$M_LOG" >&2 || true; fail "$1 failed (exit $M_EXIT)"; }; }
