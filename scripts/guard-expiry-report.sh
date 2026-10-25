#!/usr/bin/env bash
# guard-expiry-report.sh -- the only place a guard's expiry dates meet the
# calendar (docs/guard-rollout-contract.md rule 1). Runs on the nightly
# schedule on main, never on a PR or in the merge queue.
#
# It evaluates every dated exemption against today:
#   - Go: every Test*NotExpired test in every package that calls
#     guardrules.CheckExpiry, with KEYORIX_GUARD_EXPIRY_TODAY set
#     (full-row-write and child-parent-liveness pending rows,
#     knownOpenTolerances, NamedLockPendingExpires, ADR open decisions);
#   - shell: TEMPORARY rows of scripts/ci-test-legs.sh's exclusion tables,
#     which expire 30 days after their "added" date.
# A row is "due" when it expires within 7 days (it is valid through the end
# of its day), "expired" after that.
#
# Usage: scripts/guard-expiry-report.sh [--today YYYY-MM-DD] [--out FILE]
#   --out writes the Markdown report (for the nightly issue) to FILE;
#   progress goes to stderr either way.
# Exit: 0 nothing due, 1 something due (warn), 2 something expired,
#       3 the check itself failed (a test failed for another reason).
set -euo pipefail

today="" out=""
while [ $# -gt 0 ]; do
	case "$1" in
	--today) today="$2"; shift 2 ;;
	--out) out="$2"; shift 2 ;;
	*) echo "usage: $0 [--today YYYY-MM-DD] [--out FILE]" >&2; exit 3 ;;
	esac
done
[ -n "$today" ] || today=$(date -u +%Y-%m-%d)
[[ "$today" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || { echo "guard-expiry-report: --today must be YYYY-MM-DD, got '$today'" >&2; exit 3; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tsv="$work/rows.tsv"
: >"$tsv"

pkgs=()
while IFS= read -r f; do
	d=$(dirname "$f")
	case " ${pkgs[*]:-} " in *" ./$d "*) ;; *) pkgs+=("./$d") ;; esac
done < <(grep -rlE 'guardrules\.CheckExpiry\(' --include='*_test.go' --exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.scratch . | sed 's#^\./##' | sort)
[ "${#pkgs[@]}" -gt 0 ] || { echo "guard-expiry-report: found no package calling guardrules.CheckExpiry; the search is broken" >&2; exit 3; }

echo "guard-expiry-report: today=$today; running Test*NotExpired in ${#pkgs[@]} package(s): ${pkgs[*]}" >&2
go_rc=0
KEYORIX_GUARD_EXPIRY_TODAY="$today" KEYORIX_GUARD_EXPIRY_REPORT="$tsv" \
	go test -count=1 -run 'NotExpired$' "${pkgs[@]}" >"$work/go.log" 2>&1 || go_rc=$?
ran=$(grep -cE '^(ok|FAIL|---)' "$work/go.log" || true)
echo "guard-expiry-report: go test exit $go_rc ($ran result lines)" >&2

echo "guard-expiry-report: checking TEMPORARY rows in scripts/ci-test-legs.sh (30-day budget)" >&2
# shellcheck source=scripts/ci-test-legs.sh
source scripts/ci-test-legs.sh
{ exclusion_entries | sed 's/^/exclusion_entries|/'; coverage_floor_exclusions | sed 's/^/coverage_floor_exclusions|/'; } |
	python3 -c '
import sys, datetime
today = datetime.date.fromisoformat(sys.argv[1])
for line in sys.stdin:
    src, pattern, kind, reason, issue, added = (line.rstrip("\n").split("|") + [""] * 6)[:6]
    if kind != "TEMPORARY":
        continue
    exp = datetime.date.fromisoformat(added) + datetime.timedelta(days=30)
    days = (exp - today).days
    state = "expired" if days < 0 else "due" if days <= 7 else ""
    if state:
        print("\t".join([state, str(days), exp.isoformat(), "scripts/ci-test-legs.sh " + src, pattern, (reason + " " + issue).strip(), "exclusion-freshness"]))
' "$today" >>"$tsv"

due=$(grep -c '^due' "$tsv" || true)
expired=$(grep -c '^expired' "$tsv" || true)
report() {
	echo "Guard expiry check for **$today** (warns 7 days ahead; see docs/guard-rollout-contract.md)."
	echo
	if [ "$((due + expired))" -gt 0 ]; then
		echo "| state | days left | expires | where | what | note |"
		echo "|---|---|---|---|---|---|"
		sort -t$'\t' -k2,2n "$tsv" | awk -F'\t' '{ printf "| %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6 }'
		echo
		echo "Resolve each row (delete it once its fix merged) or renew it with a stated reason. PR checks never read these dates, so nothing is blocked; this issue is the only signal."
	else
		echo "No dated exemption expires within 7 days."
	fi
	if [ "$go_rc" -ne 0 ] && [ "$expired" -eq 0 ]; then
		echo
		echo "**The check itself failed** (go test exit $go_rc with no expired row):"
		echo '```'
		grep -E -- '--- FAIL|^FAIL|panic:|cannot|undefined' "$work/go.log" | head -20
		echo '```'
	fi
}
if [ -n "$out" ]; then report >"$out"; else report; fi
echo "guard-expiry-report: $due due, $expired expired" >&2

[ "$go_rc" -eq 0 ] || [ "$expired" -gt 0 ] || exit 3
[ "$expired" -eq 0 ] || exit 2
[ "$due" -eq 0 ] || exit 1
exit 0
