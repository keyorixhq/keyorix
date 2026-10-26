#!/usr/bin/env bash
# guard-rollout-status.sh -- docs/guard-rollout-contract.md rule 2: run every
# report-only guard (one docs/guard-rollout.d/<Test>.tsv row each) in enforce
# mode and print one verdict per guard. The nightly workflow runs it on main
# and keeps the output as an artifact; the coordinator's promotion script
# deletes the rows of guards that are at least a day on main and passed here.
#
# Usage: scripts/guard-rollout-status.sh   (from the repository root)
# Output (stdout, TSV): test  package  introduced_by  pass|fail
# Exit: 0 every listed guard passes (or none is listed), 1 one fails, 2 setup error.
set -euo pipefail

rows=(docs/guard-rollout.d/*.tsv)
if [ ! -e "${rows[0]}" ]; then
	echo "guard-rollout-status: no report-only guard listed" >&2
	exit 0
fi
echo "guard-rollout-status: ${#rows[@]} report-only guard(s), running each with KEYORIX_GUARD_ROLLOUT=enforce" >&2
log=$(mktemp)
trap 'rm -f "$log"' EXIT
fails=0
for f in "${rows[@]}"; do
	row=$(grep -vE '^[[:space:]]*(#|$)' "$f" || true)
	IFS=$'\t' read -r test pkg pr _ <<<"$row"
	if [ -z "${test:-}" ] || [ ! -d "${pkg:-/nonexistent}" ]; then
		echo "guard-rollout-status: $f: malformed row or missing package '${pkg:-}'" >&2
		exit 2
	fi
	verdict=pass
	KEYORIX_GUARD_ROLLOUT=enforce go test -count=1 -v -run "^${test}\$" "./$pkg" >"$log" 2>&1 || verdict=fail
	if ! grep -q -- "--- PASS: ${test} \|--- FAIL: ${test} " "$log" && [ "$verdict" = pass ]; then
		verdict=fail # the test did not run at all: renamed or deleted
		echo "guard-rollout-status: $test did not run in ./$pkg" >&2
	fi
	if [ "$verdict" = fail ]; then
		fails=$((fails + 1))
		grep -E -- '--- FAIL|_test\.go:[0-9]+:' "$log" | head -5 >&2 || true
	fi
	printf '%s\t%s\t%s\t%s\n' "$test" "$pkg" "$pr" "$verdict"
	echo "guard-rollout-status: $test: $verdict" >&2
done
[ "$fails" -eq 0 ]
