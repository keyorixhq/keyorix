#!/usr/bin/env bash
# footprint-check-selftest.sh -- red/green proof for scripts/ci/footprint-check.sh
# (run it via `footprint-check.sh --self-test`). A guard nobody has watched fail
# is not a guard: this drives the REAL check (real builds, a real 2 s idle server)
# against deliberately generated budgets and asserts the exit code and the verdict
# line of each case. It never reads the committed budget.
#
#   green: generous limits                        -> exit 0, OK lines, "within budget"
#   red:   server_bytes = 1                       -> exit 1, "server binary ... FAIL"
#   red:   cli_bytes = 1                          -> exit 1, "CLI binary ... FAIL"
#   red:   idle_rss_kib = 1                       -> exit 1, "idle RSS ... FAIL"
#   red:   no row for the platform (fail closed)  -> exit 1, "no server_bytes budget"
#   green: idle_rss_kib null                      -> exit 0, "SKIP idle RSS"
#   red:   idle_rss_kib null with --require-rss   -> exit 1, "--require-rss"
#
# What it does not prove: that the committed limits are sensible (that is the
# measured-value + headroom rule in the budget file) or the 30 s / 3-run protocol
# (the self-test uses 1 run and 2 s idle to stay cheap).
set -uo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root" || exit 2
check="scripts/ci/footprint-check.sh"
host="$(go env GOOS)/$(go env GOARCH)"
work="$(mktemp -d "${TMPDIR:-/tmp}/fpselftest.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# mkbudget <file> <platform> <server> <cli> <rss>   (rss "null" allowed)
mkbudget() {
  printf '{"platforms": {"%s": {"server_bytes": %s, "cli_bytes": %s, "idle_rss_kib": %s}}}\n' "$2" "$3" "$4" "$5" >"$1"
}

fails=0
# expect <name> <want-exit> <want-regex> <budget-file> <check args...>
expect() {
  local name="$1" want="$2" re="$3" bf="$4"
  shift 4
  local out rc=0
  out="$("$check" --budget "$bf" --runs 1 --idle 2 "$@" 2>&1)" || rc=$?
  if [ "$rc" -eq "$want" ] && printf '%s' "$out" | grep -Eq "$re"; then
    echo "selftest: PASS  $name (exit $rc, matched /$re/)"
  else
    echo "selftest: FAIL  $name: want exit $want and /$re/, got exit $rc" >&2
    printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fails=$((fails + 1))
  fi
}

big=1000000000000
mkbudget "$work/green.json" "$host" "$big" "$big" 1000000000
mkbudget "$work/red-server.json" "$host" 1 "$big" 1000000000
mkbudget "$work/red-cli.json" "$host" "$big" 1 1000000000
mkbudget "$work/red-rss.json" "$host" "$big" "$big" 1
mkbudget "$work/no-row.json" "no/such" "$big" "$big" 1000000000
mkbudget "$work/null-rss.json" "$host" "$big" "$big" null

expect "green (sizes + rss)"          0 'within budget'                      "$work/green.json"
expect "red: server over budget"      1 'server binary .*FAIL'               "$work/red-server.json" --skip-rss
expect "red: CLI over budget"         1 'CLI binary .*FAIL'                  "$work/red-cli.json" --skip-rss
expect "red: idle RSS over budget"    1 'idle RSS .*FAIL'                    "$work/red-rss.json" --skip-size
expect "red: no platform row"         1 'no server_bytes budget'             "$work/no-row.json" --skip-rss
expect "green: null RSS is skipped"   0 'SKIP idle RSS'                      "$work/null-rss.json" --skip-size
expect "red: null RSS + --require-rss" 1 '\-\-require-rss'                   "$work/null-rss.json" --skip-size --require-rss

if [ "$fails" -ne 0 ]; then
  echo "selftest: $fails case(s) FAILED" >&2
  exit 1
fi
echo "selftest: all cases passed (red and green)"
