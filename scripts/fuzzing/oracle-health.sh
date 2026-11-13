#!/usr/bin/env bash
# oracle-health.sh — repeatable mutation-testing regression check for the hardened
# fuzz oracles.
#
# It runs tools/oraclehealth (a stdlib-only AST mutation harness) over the fixed
# target list in scripts/fuzzing/oracle-health-baseline.tsv, each target against the
# shared equivalent/dead-mutant allowlist, then compares every measured kill-rate to
# the committed baseline. It exits non-zero if a target's kill-rate is below
# kill_rate - tolerance, or if a baseline target is missing from the run.
#
# This is NOT wired into CI or any workflow: it recompiles a package per mutant and
# fuzzes each one, which is too heavy for the per-PR path. It is a nightly / on-demand
# job. Runtime on pve01 (nice -n 10, GOMAXPROCS=2, -parallel 2, serial mutants): the
# three targets at fuzztime=15s / max=10 take ~10-13 min wall, plus a one-time ~1 min
# module copy — comfortably inside one nightly slot. Measure a fresh run with `time`.
#
# Usage:
#   scripts/fuzzing/oracle-health.sh                 # run + compare against baseline
#   scripts/fuzzing/oracle-health.sh --record        # run + REWRITE the baseline rates
#                                                    #   (keeps funcs/budget/tolerance;
#                                                    #    only for a deliberate re-baseline)
#   WORK=/path/to/scratch scripts/fuzzing/oracle-health.sh   # reuse a copy dir
#
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

BASELINE="scripts/fuzzing/oracle-health-baseline.tsv"
ALLOWLIST="tools/oraclehealth/oracle-health-allowlist.tsv"
WORK="${WORK:-$(mktemp -d "${TMPDIR:-/tmp}/oracle-health-copy-XXXXXX")}"
OUTDIR="$(mktemp -d "${TMPDIR:-/tmp}/oracle-health-out-XXXXXX")"
RECORD=0
[[ "${1:-}" == "--record" ]] && RECORD=1

echo "oracle-health: baseline=$BASELINE allowlist=$ALLOWLIST work=$WORK out=$OUTDIR"

reports=()
first=1
# Read the baseline TSV as the run manifest (skip comments / header).
while IFS=$'\t' read -r target package funcs fuzztime max seed kill_rate tolerance; do
	[[ -z "$target" || "$target" == \#* || "$target" == "target" ]] && continue
	out="$OUTDIR/oh-${target}.json"
	# Copy the module once (first target), then reuse the copy with -module.
	if [[ $first -eq 1 ]]; then
		src_args=(-src . -work "$WORK")
		first=0
	else
		src_args=(-module "$WORK")
	fi
	echo "== oracle-health: $target ($package) fuzztime=$fuzztime max=$max =="
	go run ./tools/oraclehealth \
		"${src_args[@]}" \
		-pkg "$package" \
		-targets "$target" \
		-funcs "$funcs" \
		-allowlist "$ALLOWLIST" \
		-fuzztime "$fuzztime" -max "$max" -seed "$seed" \
		-out "$out"
	reports+=("$out")
done < "$BASELINE"

if [[ $RECORD -eq 1 ]]; then
	echo "oracle-health: --record: rewriting kill_rate column in $BASELINE from this run"
	tmp="$(mktemp)"
	# Keep comments/header verbatim; rewrite only the kill_rate (column 7) of data rows.
	while IFS= read -r line; do
		if [[ -z "$line" || "$line" == \#* ]]; then echo "$line"; continue; fi
		IFS=$'\t' read -r target package funcs fuzztime max seed kill_rate tolerance <<<"$line"
		if [[ "$target" == "target" ]]; then echo "$line"; continue; fi
		measured="$(go run ./tools/oraclehealth -compare -baseline "$BASELINE" "${reports[@]}" 2>/dev/null \
			| awk -F'|' -v t=" $target " '$2==t {gsub(/[ %]/,"",$4); print $4}')"
		[[ -z "$measured" ]] && measured="$kill_rate"
		printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
			"$target" "$package" "$funcs" "$fuzztime" "$max" "$seed" "$measured" "$tolerance"
	done < "$BASELINE" > "$tmp"
	mv "$tmp" "$BASELINE"
	echo "oracle-health: baseline rewritten. Review the diff before committing."
	exit 0
fi

echo "== oracle-health: comparing against baseline =="
go run ./tools/oraclehealth -compare -baseline "$BASELINE" "${reports[@]}"
