#!/usr/bin/env bash
# scripts/drills/selftest.sh -- self-test of the drill helpers (DRILL-HYGIENE-1).
#
# No server, no binaries: it sources lib.sh and stubs the commands the helpers call.
#   1. verify_audit on a LARGE output whose first line is the verdict. `echo "$out" | grep -q`
#      under `set -o pipefail` exits 141 (grep -q quits at the first match, echo gets SIGPIPE) and
#      reported a valid audit as a failure at random. The output is far above the pipe buffer, so
#      the old shape fails every time, not at random.
#   2. totp_fresh keeps the last code PER ACCOUNT: with one shared "last code", the sequence
#      A, B, A handed A's already-consumed code back (replay rejected by the server).
#   3. Guard: no `<anything> | grep -q` in scripts/drills/*.sh (the shape behind 1: the left side gets
#      SIGPIPE once grep -q exits, whatever the command is, and a failing left side is also hidden).
#
# Usage: scripts/drills/selftest.sh   (exit 0 = all cases green; run by `go test ./internal/statemap`
# through TestDrillScripts_SelfTestAndNoEchoGrepQ)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
FAILS=0
check() { # <name> <exit-status-of-the-case> (0 = pass)
    if [ "$2" -eq 0 ]; then echo "PASS: $1"; else echo "FAIL: $1"; FAILS=$((FAILS + 1)); fi
}

# --- 1. verify_audit with a large output, match on the first line ---------------------------
inst_admin() {
    echo "Verdict: VALID"
    echo "chained events: 7"
    head -c 600000 /dev/zero | tr '\0' 'x'
    echo
}
rc=0
(verify_audit selftest) >"$WORK/va.out" 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then cut -c1-80 "$WORK/va.out" | head -5; fi
check "verify_audit accepts VALID on a 600 KB output (exit $rc)" "$rc"

# --- 2. totp_fresh keeps one last code per account -------------------------------------------
DRILL_DIR="$WORK/drill"
mkdir -p "$DRILL_DIR"
totp() { cat "$WORK/code.$1"; }
printf 111111 >"$WORK/code.AAAA"
printf 222222 >"$WORK/code.BBBB"
a1="$(totp_fresh AAAA)"
b1="$(totp_fresh BBBB)"
# Replace the file atomically: a plain `printf >file` truncates first, and the 1 s poll in
# totp_fresh landing in that window read "" and accepted it as a fresh code (flaked in the queue).
(sleep 2; printf 333333 >"$WORK/code.AAAA.new"; mv "$WORK/code.AAAA.new" "$WORK/code.AAAA") &
a2="$(totp_fresh AAAA)"
wait
rc=0
{ [ "$a1" = 111111 ] && [ "$b1" = 222222 ] && [ "$a2" = 333333 ]; } || rc=1
check "totp_fresh A,B,A never replays A's code (got $a1 $b1 $a2)" "$rc"

# --- 4. skip and failure contract (DRILLS-PG-1) -----------------------------------------------
# A skipped leg prints "SKIP <backend>: <reason>" and the drill goes on; a Postgres drill given no
# database skips as a whole with exit 0; a failure exits non-zero; an unknown backend fails.
rc=0
out="$(drill_skip postgres "no witness file")" || rc=1
[ "$out" = "SKIP postgres: no witness file" ] || rc=1
check "drill_skip prints 'SKIP postgres: <reason>' (got: $out)" "$rc"

rc=0
out="$( (DRILL_BACKEND=postgres DRILL_PG_DSN_FILE="" drill_begin selftest-skip) 2>&1)" || rc=$?
case "$out" in SKIP\ postgres:\ *) ;; *) rc=1 ;; esac
check "postgres without DRILL_PG_DSN_FILE: 'SKIP postgres: ...' and exit 0 (exit $rc)" "$rc"

rc=0
(DRILL_BACKEND=mysql drill_begin selftest-badbackend) >/dev/null 2>&1 || rc=$?
ok_rc=0; [ "$rc" -ne 0 ] || ok_rc=1
check "an unknown DRILL_BACKEND exits non-zero (exit $rc)" "$ok_rc"

rc=0
(fail "selftest failure") >/dev/null 2>&1 || rc=$?
ok_rc=0; [ "$rc" -ne 0 ] || ok_rc=1
check "fail exits non-zero (exit $rc)" "$ok_rc"

# --- 3. no echo|printf ... | grep -q in the drill scripts --------------------------------------
rc=0
hits="$(grep -nE '\|[[:space:]]*grep[[:space:]]+-[a-zA-Z]*q' "$HERE"/*.sh | grep -v 'selftest.sh' || true)"
if [ -n "$hits" ]; then
    echo "$hits"
    echo "use: out=\"\$(cmd)\" then grep -q... <<<\"\$out\" (here-string) instead of cmd | grep -q..."
    rc=1
fi
check "no 'cmd | grep -q' under scripts/drills" "$rc"

[ "$FAILS" -eq 0 ] || { echo "drills selftest: $FAILS case(s) failed"; exit 1; }
echo "drills selftest: all cases green"
