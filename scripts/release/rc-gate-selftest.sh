#!/usr/bin/env bash
# scripts/release/rc-gate-selftest.sh -- self-test of rc-gate.sh (RC-GATE-DRILLS-NOV-1).
#
# No network, no real release, no server: rc-gate.sh runs against a fixture release tree
# (RC_GATE_ASSET_BASE), a stub verify-release.sh and stub drills that record what the gate handed
# them. What it calibrates, red AND green, is the exit status and the result lines:
#   1. green: every leg PASS, exit 0; the previous release is picked from a releases listing (newest
#      FINAL below the candidate, numeric order, no draft, no pre-release); the drills get the
#      previous server as DRILL_OLD_SERVER_BIN, the candidate's server and CLI, the right PostgreSQL
#      files, and a PostgreSQL file in the caller's environment never reaches a SQLite leg;
#   2. red: a failing drill leg, a failing verify-release (no drill may start), a previous binary
#      that does not match its checksums.txt (no drill may start), a candidate with a missing asset,
#      a drill that exits 0 without saying PASSED or SKIP (fail closed);
#   3. SKIP: no PostgreSQL directory gives named SKIP legs and exit 0, --strict exit 2; a drill that
#      skips a sub-leg is PASS with the SKIP in the detail;
#   4. the REAL verify-release.sh on a fixture directory missing assets fails the gate;
#   5. fetch_asset and pick_previous on their own (reuse, --refresh, partial file, bad name);
#   6. --check-result accepts the green TSV and refuses a FAIL, a SKIP, a missing leg, another
#      candidate and a file that is not a gate result.
#
# Usage: scripts/release/rc-gate-selftest.sh   (exit 0 = all cases green)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE="$HERE/rc-gate.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
check() { # <name> <exit-status-of-the-case> (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; FAILS=$((FAILS + 1)); fi
}
sha256_of() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

PLAT=testos_testarch
CAND=v1.0.0-rc.1
PREV=v0.9.10

# --- fixture release tree --------------------------------------------------------------------------
mk_world() { # TAG: the files a tag publishes, as far as the gate reads them
    local d="$WORK/assets/$1" f
    mkdir -p "$d"
    for f in keyorix-server keyorix; do
        printf '#!/bin/sh\necho "%s %s (selftest fixture)"\n' "$f" "$1" >"$d/${f}_$PLAT"
        chmod +x "$d/${f}_$PLAT"
    done
    printf '{"bomFormat":"CycloneDX"}\n' >"$d/keyorix_${PLAT}_sbom.cdx.json"
    for f in keyorix-server_$PLAT keyorix_$PLAT keyorix_${PLAT}_sbom.cdx.json; do
        printf '%s  %s\n' "$(sha256_of "$d/$f")" "$f"
    done >"$d/checksums.txt"
    printf 'sig\n' >"$d/checksums.txt.sig"
    printf 'pem\n' >"$d/checksums.txt.pem"
}
mk_world "$CAND"
mk_world "$PREV"
cat >"$WORK/releases.json" <<'EOF'
[
 {"tag_name": "v1.0.0",       "draft": false, "prerelease": false},
 {"tag_name": "v1.0.0-rc.1",  "draft": false, "prerelease": true},
 {"tag_name": "v0.9.11",      "draft": true,  "prerelease": false},
 {"tag_name": "v0.9.10",      "draft": false, "prerelease": false},
 {"tag_name": "v0.9.9",       "draft": false, "prerelease": false}
]
EOF
mkdir -p "$WORK/pg"
for n in 1 2 3 4; do printf 'postgres://u:p@127.0.0.1:5432/db%s\n' "$n" >"$WORK/pg/dsn$n.txt"; done

# --- stubs: verify-release.sh and the two drills --------------------------------------------------------
mkdir -p "$WORK/stub/drills"
cat >"$WORK/stub/verify.sh" <<'EOF'
#!/usr/bin/env bash
echo "$*" >"$STUB_RECORD_DIR/verify.args"
case ${STUB_VERIFY_RC:-0} in
    0) echo "PASS  release.assets  stub" ;;
    1) echo "FAIL  release.checksums.binaries  stub" ;;
    2) echo "SKIP  release.signature.cosign  stub" ;;
esac
exit "${STUB_VERIFY_RC:-0}"
EOF
for s in upgrade backup-restore; do
    cat >"$WORK/stub/drills/$s.sh" <<'EOF'
#!/usr/bin/env bash
name="$(basename "$0" .sh)"
var="STUB_MODE_$(printf '%s_%s' "$name" "$DRILL_BACKEND" | tr '-' '_')"
mode="${!var:-pass}"
{
    echo "OLD=$DRILL_OLD_SERVER_BIN"
    echo "NEW=$DRILL_SERVER_BIN"
    echo "CLI=$DRILL_CLI_BIN"
    echo "PG=${DRILL_PG_DSN_FILE:-}|${DRILL_PG_DSN_FILE2:-}|${DRILL_PG_DSN_FILE3:-}"
} >"$STUB_RECORD_DIR/$name.$DRILL_BACKEND"
label="$(printf '%s' "$name" | tr 'a-z-' 'A-Z ') DRILL"
case "$mode" in
    pass) echo "    elapsed: 1s (backend: $DRILL_BACKEND)"; echo "$label PASSED" ;;
    fail) echo "DRILL FAILED: stub boom" >&2; exit 1 ;;
    skip) echo "SKIP $DRILL_BACKEND: stub has no database" ;;
    silent) exit 0 ;;
    partial) echo "SKIP $DRILL_BACKEND: stub tamper leg"; echo "$label PASSED" ;;
esac
EOF
    chmod +x "$WORK/stub/drills/$s.sh"
done
chmod +x "$WORK/stub/verify.sh"

# gate NAME [VAR=value ...] [-- rc-gate arguments]: runs the gate against the fixtures; sets GRC (exit
# status), GOUT (stdout file), REC (what the stubs recorded) and TSV
gate() {
    local name="$1"
    shift
    local -a envs=()
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done
    [ $# -eq 0 ] || shift
    REC="$WORK/rec-$name"
    GOUT="$WORK/out-$name.txt"
    TSV="$WORK/dir-$name/rc-gate-result.tsv"
    mkdir -p "$REC"
    GRC=0
    env RC_GATE_ASSET_BASE="$WORK/assets" RC_GATE_PLATFORM="$PLAT" RC_GATE_VERIFY_SCRIPT="$WORK/stub/verify.sh" \
        RC_GATE_DRILLS_DIR="$WORK/stub/drills" RC_GATE_RELEASES_JSON="$WORK/releases.json" \
        RC_GATE_PG_DSN_DIR="$WORK/pg" STUB_RECORD_DIR="$REC" DRILL_PG_DSN_FILE=/leak/must-not-reach-sqlite \
        ${envs[@]+"${envs[@]}"} \
        "$GATE" --dir "$WORK/dir-$name" "$@" >"$GOUT" 2>"$WORK/err-$name.txt" || GRC=$?
}
leg_status() { awk -F'\t' -v l="$1" '$1 == l { s = $2 } END { print s }' "$TSV"; } # LEG -> PASS|FAIL|SKIP|""
leg_detail() { awk -F'\t' -v l="$1" '$1 == l { s = $3 } END { print s }' "$TSV"; }
drills_started() { find "$REC" -name 'upgrade.*' -o -name 'backup-restore.*' | wc -l | tr -d ' '; }

# --- 1. green ---------------------------------------------------------------------------------------
gate green -- "$CAND"
rc=0
[ "$GRC" -eq 0 ] || rc=1
for leg in download verify-release previous.checksum upgrade.sqlite upgrade.postgres backup-restore.sqlite backup-restore.postgres; do
    [ "$(leg_status "$leg")" = PASS ] || { echo "  $leg: '$(leg_status "$leg")'"; rc=1; }
done
grep -q '^RC GATE PASSED' "$GOUT" || rc=1
check "green: every leg PASS, exit 0 (exit $GRC)" "$rc"

rc=0
head -n 1 "$TSV" | grep -q "candidate=$CAND.previous=$PREV.platform=$PLAT" || { head -n 1 "$TSV"; rc=1; }
check "green: previous = newest FINAL below the candidate, in numeric order (v0.9.10, not v0.9.9, no draft, no pre-release)" "$rc"

rc=0
grep -qx "OLD=$WORK/dir-green/$PREV/keyorix-server_$PLAT" "$REC/upgrade.sqlite" || rc=1
grep -qx "NEW=$WORK/dir-green/$CAND/keyorix-server_$PLAT" "$REC/upgrade.sqlite" || rc=1
grep -qx "CLI=$WORK/dir-green/$CAND/keyorix_$PLAT" "$REC/upgrade.sqlite" || rc=1
check "green: DRILL_OLD_SERVER_BIN = previous server, DRILL_SERVER_BIN and DRILL_CLI_BIN = candidate" "$rc"

rc=0
grep -qx "PG=||" "$REC/upgrade.sqlite" || { cat "$REC/upgrade.sqlite"; rc=1; }
grep -qx "PG=||" "$REC/backup-restore.sqlite" || rc=1
grep -qx "PG=$WORK/pg/dsn1.txt||" "$REC/upgrade.postgres" || rc=1
grep -qx "PG=$WORK/pg/dsn2.txt|$WORK/pg/dsn3.txt|$WORK/pg/dsn4.txt" "$REC/backup-restore.postgres" || rc=1
check "green: PostgreSQL files per leg (1 | 2,3,4); the caller's DRILL_PG_DSN_FILE never reaches a SQLite leg" "$rc"

rc=0
grep -q -- "--assets-dir $WORK/dir-green/$CAND" "$REC/verify.args" || rc=1
grep -q -- "$CAND\$" "$REC/verify.args" || rc=1
check "green: verify-release runs on the downloaded candidate directory" "$rc"

# --- 2. red -----------------------------------------------------------------------------------------
gate red-drill STUB_MODE_upgrade_postgres=fail -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status upgrade.postgres)" = FAIL ] || rc=1
[ "$(leg_status backup-restore.postgres)" = PASS ] || rc=1
grep -q '^RC GATE FAILED' "$GOUT" || rc=1
leg_detail upgrade.postgres | grep -q 'stub boom' || rc=1
check "red: a failing drill leg is FAIL, exit 1, the other legs still run (exit $GRC)" "$rc"

gate red-verify STUB_VERIFY_RC=1 -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status verify-release)" = FAIL ] || rc=1
[ "$(drills_started)" = 0 ] || { echo "  a drill started after verify-release FAILED"; rc=1; }
[ "$(leg_status upgrade.sqlite)" = SKIP ] || rc=1
leg_detail upgrade.sqlite | grep -q 'verify-release FAILED' || rc=1
check "red: verify-release FAIL stops the gate before any drill starts (exit $GRC)" "$rc"

gate verify-incomplete STUB_VERIFY_RC=2 -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 0 ] || rc=1
[ "$(leg_status verify-release)" = SKIP ] || rc=1
leg_detail verify-release | grep -q 'release.signature.cosign' || rc=1
[ "$(leg_status upgrade.sqlite)" = PASS ] || rc=1
check "verify-release INCOMPLETE (exit 2) is a SKIP naming the checks, the drills still run, exit 0 (exit $GRC)" "$rc"

# a previous binary that was changed after download (the file is reused from the directory, then hashed)
mkdir -p "$WORK/dir-red-prev/$PREV"
cp "$WORK/assets/$PREV/checksums.txt" "$WORK/assets/$PREV/checksums.txt.sig" "$WORK/assets/$PREV/checksums.txt.pem" "$WORK/dir-red-prev/$PREV/"
cp "$WORK/assets/$PREV/keyorix_$PLAT" "$WORK/dir-red-prev/$PREV/"
{ cat "$WORK/assets/$PREV/keyorix-server_$PLAT"; echo "# flipped"; } >"$WORK/dir-red-prev/$PREV/keyorix-server_$PLAT"
gate red-prev -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status previous.checksum)" = FAIL ] || rc=1
[ "$(drills_started)" = 0 ] || { echo "  a drill started on a previous binary that fails its checksum"; rc=1; }
check "red: a previous binary that differs from its checksums.txt fails the gate before any drill (exit $GRC)" "$rc"

# a candidate whose checksums.txt names an asset the release does not have (real v0.96.3 checksums.txt)
mkdir -p "$WORK/assets/v0.96.3"
cp "$HERE/testdata/real-v0.96.3/assets/checksums.txt" "$HERE/testdata/real-v0.96.3/assets/checksums.txt.sig" "$HERE/testdata/real-v0.96.3/assets/checksums.txt.pem" "$WORK/assets/v0.96.3/"
gate red-missing -- v0.96.3 "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status download)" = FAIL ] || rc=1
[ "$(drills_started)" = 0 ] || rc=1
leg_detail download | grep -q 'not available' || rc=1
check "red: a release without the assets its own checksums.txt lists fails at the download (real v0.96.3 checksums.txt, exit $GRC)" "$rc"

gate red-silent STUB_MODE_backup_restore_sqlite=silent -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status backup-restore.sqlite)" = FAIL ] || rc=1
leg_detail backup-restore.sqlite | grep -q 'neither' || rc=1
check "red: a drill that exits 0 without PASSED or SKIP is a FAIL (fail closed, exit $GRC)" "$rc"

# --- 3. SKIP ----------------------------------------------------------------------------------------
gate skip-pg RC_GATE_PG_DSN_DIR= -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 0 ] || rc=1
[ "$(leg_status upgrade.postgres)" = SKIP ] || rc=1
[ "$(leg_status backup-restore.postgres)" = SKIP ] || rc=1
leg_detail upgrade.postgres | grep -q 'RC_GATE_PG_DSN_DIR' || rc=1
[ ! -e "$REC/upgrade.postgres" ] || rc=1
grep -q '^RC GATE PASSED with 2 SKIP' "$GOUT" || rc=1
check "SKIP: no PostgreSQL directory gives two named SKIP legs, exit 0 (exit $GRC)" "$rc"

gate skip-strict RC_GATE_PG_DSN_DIR= -- --strict "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 2 ] || rc=1
grep -q '^RC GATE INCOMPLETE' "$GOUT" || rc=1
check "SKIP: --strict turns a SKIP into exit 2 (exit $GRC)" "$rc"

gate skip-whole STUB_MODE_upgrade_postgres=skip -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 0 ] || rc=1
[ "$(leg_status upgrade.postgres)" = SKIP ] || rc=1
leg_detail upgrade.postgres | grep -q 'SKIP postgres: stub has no database' || rc=1
check "SKIP: a drill that skips as a whole is a SKIP leg carrying the drill's reason (exit $GRC)" "$rc"

gate skip-partial STUB_MODE_backup_restore_postgres=partial -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 0 ] || rc=1
[ "$(leg_status backup-restore.postgres)" = PASS ] || rc=1
leg_detail backup-restore.postgres | grep -q 'partial SKIP: SKIP postgres: stub tamper leg' || rc=1
check "SKIP: a skipped sub-leg inside a PASSED drill stays visible in the detail (exit $GRC)" "$rc"

rm -f "$WORK/pg/dsn4.txt"
gate three-dsn -- "$CAND" "$PREV"
rc=0
grep -qx "PG=$WORK/pg/dsn2.txt|$WORK/pg/dsn3.txt|" "$REC/backup-restore.postgres" || { cat "$REC/backup-restore.postgres" 2>/dev/null; rc=1; }
check "without dsn4.txt backup-restore gets two PostgreSQL files (the drill reports its own tamper-leg SKIP)" "$rc"
printf 'postgres://u:p@127.0.0.1:5432/db4\n' >"$WORK/pg/dsn4.txt"

# --- 4. the REAL verify-release.sh -------------------------------------------------------------------
gate real-verify RC_GATE_VERIFY_SCRIPT="$HERE/verify-release.sh" RC_GATE_VERIFY_ARGS="--offline --no-cosign --no-gh --skip-images --skip-charts" -- "$CAND" "$PREV"
rc=0
[ "$GRC" -eq 1 ] || rc=1
[ "$(leg_status verify-release)" = FAIL ] || rc=1
leg_detail verify-release | grep -q 'release.assets' || rc=1
[ "$(drills_started)" = 0 ] || rc=1
check "the real verify-release.sh on a directory that is not a full release FAILs the gate, no drill starts (exit $GRC)" "$rc"

# --- 5. fetch_asset and pick_previous on their own ----------------------------------------------------
rc=0
(
    ptag="$PREV" # rc-gate.sh resets CAND and PREV when sourced
    # shellcheck source=rc-gate.sh
    # shellcheck disable=SC1091
    source "$GATE"
    set +e
    # shellcheck disable=SC2034 # read by fetch_asset
    ASSET_BASE="$WORK/assets"
    REFRESH=0
    d="$WORK/fetch"
    fetch_asset "$ptag" checksums.txt "$d" 2>/dev/null || exit 1
    [ -s "$d/checksums.txt" ] || exit 2
    echo changed >"$d/checksums.txt"
    fetch_asset "$ptag" checksums.txt "$d" 2>/dev/null || exit 3
    [ "$(cat "$d/checksums.txt")" = changed ] || exit 4 # reused, not downloaded again
    # shellcheck disable=SC2034 # read by fetch_asset
    REFRESH=1
    fetch_asset "$ptag" checksums.txt "$d" 2>/dev/null || exit 5
    [ "$(cat "$d/checksums.txt")" != changed ] || exit 6 # --refresh replaces it
    if fetch_asset "$ptag" no-such-asset "$d" 2>/dev/null; then exit 7; fi
    ls "$d"/*.part >/dev/null 2>&1 && exit 8 # no partial file left behind
    if fetch_asset "$ptag" ../x "$d" 2>/dev/null; then exit 9; fi
    exit 0
) || rc=$?
check "fetch_asset: copy, reuse, --refresh, missing asset leaves no .part, '../x' refused (exit $rc)" "$rc"

rc=0
(
    # shellcheck source=rc-gate.sh
    # shellcheck disable=SC1091
    source "$GATE"
    set +e
    [ "$(pick_previous v1.0.0 "$WORK/releases.json")" = v0.9.10 ] || exit 1
    [ "$(pick_previous v0.9.10 "$WORK/releases.json")" = v0.9.9 ] || exit 2
    if pick_previous v0.9.9 "$WORK/releases.json" >/dev/null; then exit 3; fi
    exit 0
) || rc=$?
check "pick_previous: a final candidate gets the next lower release, the oldest has none (exit $rc)" "$rc"

# --- 6. --check-result -------------------------------------------------------------------------------
GREEN="$WORK/dir-green/rc-gate-result.tsv"
chk() { # [--allow-skip] FILE [CANDIDATE]
    local -a pre=()
    if [ "$1" = "--allow-skip" ]; then pre=(--allow-skip); shift; fi
    "$GATE" ${pre[@]+"${pre[@]}"} --check-result "$@" >/dev/null 2>&1
}
rc=0
chk "$GREEN" "$CAND" || rc=1
check "--check-result accepts the green result for its candidate" "$rc"

rc=0
chk "$WORK/dir-red-drill/rc-gate-result.tsv" "$CAND" && rc=1
check "--check-result refuses a result with a FAIL" "$rc"

rc=0
chk "$WORK/dir-skip-pg/rc-gate-result.tsv" "$CAND" && rc=1
chk --allow-skip "$WORK/dir-skip-pg/rc-gate-result.tsv" "$CAND" || rc=1
check "--check-result refuses a SKIP unless --allow-skip" "$rc"

rc=0
grep -v '^backup-restore.postgres' "$GREEN" >"$WORK/missing-leg.tsv"
chk "$WORK/missing-leg.tsv" "$CAND" && rc=1
check "--check-result refuses a result that lacks a leg" "$rc"

rc=0
chk "$GREEN" v9.9.9 && rc=1
check "--check-result refuses a result made for another candidate" "$rc"

rc=0
printf 'leg\tstatus\tdetail\nupgrade.sqlite\tPASS\tx\n' >"$WORK/not-a-result.tsv"
chk "$WORK/not-a-result.tsv" && rc=1
check "--check-result refuses a file that is not an rc-gate result" "$rc"

[ "$FAILS" -eq 0 ] || { echo "rc-gate selftest: $FAILS case(s) failed"; exit 1; }
echo "rc-gate selftest: all cases green"
