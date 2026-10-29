#!/usr/bin/env bash
# scripts/release-qa/scenario_restore_scale.sh -- backup/restore/migrate at
# scale (#3462). Generates a large SQLite database (scalegen: secret
# versions + chained audit events), then measures peak RSS and wall time of:
#   1. admin backup                (SQLite source)
#   2. admin restore -> SQLite
#   3. admin restore -> PostgreSQL (the SQLite -> PostgreSQL migration path)
#   4. admin backup                (PostgreSQL source)
#   5. admin restore -> SQLite     (the PostgreSQL -> SQLite direction)
# Steps 3-5 need an EMPTY PostgreSQL database DSN; pass "-" to skip them.
# Every restore must end with verify-audit VALID.
#
# Results go to <work-dir>/results.tsv (step, rows, seconds, peak RSS KiB).
# Keep the numbers in reports, never in repo docs.
#
# Usage: scenario_restore_scale.sh <server-bin> <postgres-dsn|-> <work-dir> \
#          [versions=300000] [audit=300000] [secrets=1000]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVER_BIN="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
PG_DSN="$2"
WORK="$3"
VERSIONS="${4:-300000}"
AUDITS="${5:-300000}"
SECRETS="${6:-1000}"
mkdir -p "$WORK"
WORK="$(cd "$WORK" && pwd)"
RESULTS="$WORK/results.tsv"
# Fixed default so a generated source (KEYORIX_QA_REUSE_SRC) stays usable; throwaway data.
export KEYORIX_MASTER_PASSWORD="${KEYORIX_MASTER_PASSWORD:-scale-master-passphrase-1234}"

fail() { echo "SCALE SCENARIO FAILED: $1" >&2; exit 1; }
step() { echo "==> $1" >&2; }

cfg() { # <dir> <storage-yaml>
    mkdir -p "$1/keys" && chmod 700 "$1/keys"
    printf 'storage:\n%s\n  encryption:\n    enabled: true\n    dek_path: "keys/dek.key"\n    salt_path: "keys/kek.salt"\n' "$2" > "$1/keyorix.yaml"
}

# measure <label> <dir> <cmd...>: run in <dir>, record seconds + peak RSS
# (KiB) from getrusage(RUSAGE_CHILDREN) -- /usr/bin/time -l needs a sysctl
# a sandboxed macOS session cannot read.
measure() {
    local label="$1" dir="$2"
    shift 2
    local out="$WORK/$label.log" m
    step "$label"
    m="$(cd "$dir" && python3 -c '
import resource, subprocess, sys, time
t = time.time()
with open(sys.argv[1], "w") as log:
    rc = subprocess.call(sys.argv[2:], stdout=log, stderr=subprocess.STDOUT)
rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
if sys.platform == "darwin":
    rss //= 1024  # bytes on macOS, KiB on Linux
print(f"{rc} {time.time() - t:.1f} {rss}")
' "$out" "$@")" || fail "$label: measuring wrapper"
    local rc secs rss
    read -r rc secs rss <<< "$m"
    [ "$rc" = 0 ] || { tail -20 "$out" >&2; fail "$label (exit $rc)"; }
    printf '%s\t%s\t%s\t%s\n' "$label" "$((VERSIONS + AUDITS))" "$secs" "$rss" >> "$RESULTS"
    echo "    ${label}: $secs s, peak RSS $rss KiB" >&2
}

printf 'step\tgenerated_rows\tseconds\tpeak_rss_kib\n' > "$RESULTS"

if [ -z "${KEYORIX_QA_REUSE_SRC:-}" ]; then
    step "build scalegen"
    (cd "$REPO_ROOT" && go build -o "$WORK/scalegen" ./scripts/release-qa/scalegen) || fail "build scalegen"
fi

SRC="$WORK/src"
if [ -n "${KEYORIX_QA_REUSE_SRC:-}" ] && [ -f "$SRC/keyorix.db" ]; then
    step "reusing the generated source database in $SRC (KEYORIX_QA_REUSE_SRC)"
else
    cfg "$SRC" "  type: sqlite
  database:
    path: \"$SRC/keyorix.db\""
    (cd "$SRC" && "$SERVER_BIN" admin encryption init --config keyorix.yaml >/dev/null 2>&1) || fail "encryption init"
    (cd "$SRC" && "$SERVER_BIN" admin migrate --config keyorix.yaml >/dev/null 2>&1) || fail "migrate"
    step "generate: $SECRETS secrets, $VERSIONS versions, $AUDITS audit events"
    (cd "$SRC" && "$WORK/scalegen" -config keyorix.yaml -secrets "$SECRETS" -versions "$VERSIONS" -audit "$AUDITS") \
        || fail "scalegen"
fi
ls -l "$SRC/keyorix.db" >&2

measure backup-sqlite "$SRC" "$SERVER_BIN" admin backup --config keyorix.yaml --output "$WORK/sqlite.tar.gz"
ls -l "$WORK/sqlite.tar.gz" >&2

DST="$WORK/dst-sqlite"
cfg "$DST" "  type: sqlite
  database:
    path: \"$DST/keyorix.db\""
measure restore-sqlite-to-sqlite "$DST" "$SERVER_BIN" admin restore --config keyorix.yaml --input "$WORK/sqlite.tar.gz"
grep -q 'verify-audit on the restored database: VALID' "$WORK/restore-sqlite-to-sqlite.log" || fail "SQLite restore not VALID"

if [ "$PG_DSN" != "-" ]; then
    PG="$WORK/dst-pg"
    cfg "$PG" "  type: postgres
  database:
    dsn: \"$PG_DSN\""
    measure restore-sqlite-to-postgres "$PG" "$SERVER_BIN" admin restore --config keyorix.yaml --input "$WORK/sqlite.tar.gz"
    grep -q 'verify-audit on the restored database: VALID' "$WORK/restore-sqlite-to-postgres.log" || fail "PG restore not VALID"
    measure backup-postgres "$PG" "$SERVER_BIN" admin backup --config keyorix.yaml --output "$WORK/postgres.tar.gz"
    BACK="$WORK/dst-pg-to-sqlite"
    cfg "$BACK" "  type: sqlite
  database:
    path: \"$BACK/keyorix.db\""
    measure restore-postgres-to-sqlite "$BACK" "$SERVER_BIN" admin restore --config keyorix.yaml --input "$WORK/postgres.tar.gz"
    grep -q 'verify-audit on the restored database: VALID' "$WORK/restore-postgres-to-sqlite.log" || fail "PG->SQLite restore not VALID"
fi

echo "" >&2
column -t "$RESULTS"
