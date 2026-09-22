#!/usr/bin/env bash
# Diffs a FUZZ_STATE_REPORT file against the full ENUMERABLE security-state
# tuple space for one harness, and lists which tuples were never reached.
#
# Run a fuzz target with FUZZ_STATE_REPORT=<path> set (see
# internal/fuzzutil/statereport.go) to collect the report, e.g.:
#
#   FUZZ_STATE_REPORT=/tmp/core-states.txt \
#     go test ./internal/core -fuzz=FuzzCoreOperationSequence -fuzztime=10m
#
# then diff it against the core harness's tuple space:
#
#   scripts/fuzzing/state-coverage-diff.sh /tmp/core-states.txt core
#
# The enumerable space comes from TestEnumerateCoreStateLabels /
# TestEnumerateHTTPStateLabels -- the SAME label-building functions
# (coreCurrentLabel/coreTransitionLabel, httpCurrentLabel/httpTransitionLabel)
# the harness itself calls while fuzzing, not a hand-duplicated list, so this
# can't silently drift out of sync with what the harness actually reports.
#
# `go test -fuzz` runs multiple worker processes in parallel, each with its
# own process-local dedup (see StateReport's doc comment) -- the report file
# can contain the same label more than once across workers. `sort -u` below
# is what makes "reached" a true distinct count, not an artifact of how many
# workers happened to hit a state first.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

report="${1:?usage: state-coverage-diff.sh <report-file> <core|http>}"
target="${2:?usage: state-coverage-diff.sh <report-file> <core|http>}"

if [ ! -f "$report" ]; then
	echo "report file not found: $report" >&2
	exit 1
fi

case "$target" in
core)
	pkg="./internal/core"
	testname="TestEnumerateCoreStateLabels"
	;;
http)
	pkg="./server/http"
	testname="TestEnumerateHTTPStateLabels"
	;;
*)
	echo "unknown target: $target (want core or http)" >&2
	exit 1
	;;
esac

enumerable="$(mktemp)"
reached="$(mktemp)"
trap 'rm -f "$enumerable" "$reached"' EXIT

go test "$pkg" -run "^${testname}\$" -v |
	grep '^STATE-ENUM: ' |
	sed 's/^STATE-ENUM: //' |
	sort -u >"$enumerable"

sort -u "$report" | grep -E '^(core|http)/' >"$reached" || true

total=$(wc -l <"$enumerable" | tr -d ' ')
hit=$(comm -12 "$enumerable" "$reached" | wc -l | tr -d ' ')

echo "reached ${hit} / ${total} distinct ${target} security states"
echo
echo "UNREACHED:"
comm -23 "$enumerable" "$reached"
