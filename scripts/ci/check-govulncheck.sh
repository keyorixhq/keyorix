#!/usr/bin/env bash
# scripts/ci/check-govulncheck.sh -- govulncheck with an ID-scoped allowlist
# for findings that have no upstream fix and are confirmed, documented and
# dated as not exploitable here. See docs/govulncheck-exceptions.d/README.md
# for what earns a row and the rules around adding one.
#
# Background (NEEDS ANDREI note, reports/SESSION-REVFIX-3972-4.md,
# 2026-11-06): a bare `govulncheck ./...` has no exclusion mechanism at all,
# so the day GO-2026-6909 (crewjam/saml, no fixed version) was published,
# static-analysis -- and build-and-test behind it -- went red repo-wide with
# no way to land anything, including the fix for the OTHER advisory
# published the same hour (GO-2026-6865, klauspost/compress, since bumped).
#
# `govulncheck -format json` is the only way to decide this ourselves: it
# always exits 0 regardless of what it finds (confirmed empirically against
# this repo's own main, 2026-11-06 -- text-mode `govulncheck ./...` exits 3
# on the identical build, JSON-mode exits 0; this is not documented behavior
# we're relying on by assumption, it's what v1.8.0 actually does). So this
# script, not govulncheck itself, is what fails the build.
#
# What "reachable" means here, matching govulncheck's own text-mode
# Vulnerability-vs-"doesn't appear to call" split exactly: each `finding` in
# the JSON stream carries a `trace` array. A trace of length 1 is a
# module-or-package-level match only (present, not called) -- the same
# population text mode reports as "N vulnerabilities in packages you import"
# / "in modules you require" and exits 0 for by itself. A trace of length >1
# means the call graph actually walks from this repo's own code down to the
# vulnerable symbol -- the same population text mode prints under
# "=== Symbol Results ===" and exits 3 for. Verified against this repo's own
# main on 2026-11-06: GO-2026-6860/6866/5932 (x/net, x/crypto) appear only as
# length-1 findings and text mode correctly calls them non-blocking; GO-2026-
# 6909 and GO-2026-6865 each appear BOTH as length-1 summary findings AND as
# one-or-more length->1 findings whose outermost frame is this repo's own
# code, and text mode correctly calls those two "Vulnerability #1"/"#2" and
# exits 3. A finding is treated as reachable here the moment ANY of its
# (possibly several) trace entries has length >1 -- the shorter, same-ID
# entries are just lower-detail restatements of the identical finding, not a
# separate non-reachable population to tally.
#
# This script only ever narrows what govulncheck would otherwise fail on. A
# reachable finding with no row in docs/govulncheck-exceptions.d/ fails
# exactly as a bare `govulncheck ./...` would. The expiry date on a row is
# NOT read here -- docs/guard-rollout-contract.md rule 1: a PR-time check
# never decides pass/fail from the wall clock. An expired row still passes
# this script; scripts/ci/govulncheck_exceptions_test.go's
# TestGovulncheckExceptionsNotExpired (run nightly by
# scripts/guard-expiry-report.sh, which discovers it the same way it
# discovers every other Test*NotExpired) is what actually surfaces that.
#
# Usage:
#   scripts/ci/check-govulncheck.sh                  run govulncheck for real
#   scripts/ci/check-govulncheck.sh --json-file FILE  decide from FILE instead
#                                                      of running govulncheck
#                                                      (testing only)
#   scripts/ci/check-govulncheck.sh --self-test       run
#                                                      check-govulncheck-test.sh
# Exit: 0 clean (nothing reachable, or every reachable ID is allowlisted);
#       1 a reachable, non-allowlisted finding, or govulncheck/jq itself failed.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
exceptions_dir="$repo/docs/govulncheck-exceptions.d"

if [ "${1:-}" = "--self-test" ]; then
	exec bash "$here/check-govulncheck-test.sh"
fi

command -v jq >/dev/null 2>&1 || { echo "check-govulncheck: jq is required" >&2; exit 1; }

json_file=""
if [ "${1:-}" = "--json-file" ]; then
	json_file=${2:-}
	[ -n "$json_file" ] || { echo "usage: $0 --json-file FILE" >&2; exit 1; }
elif [ $# -gt 0 ]; then
	echo "usage: $0 [--json-file FILE | --self-test]" >&2
	exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -n "$json_file" ]; then
	cp "$json_file" "$work/govulncheck.json"
else
	govulncheck_bin=$(command -v govulncheck || true)
	[ -x "${govulncheck_bin:-}" ] || govulncheck_bin="$HOME/go/bin/govulncheck"
	[ -x "$govulncheck_bin" ] || { echo "check-govulncheck: no govulncheck binary found" >&2; exit 1; }
	set +e
	"$govulncheck_bin" -format json ./... >"$work/govulncheck.json" 2>"$work/govulncheck.stderr"
	gv_rc=$?
	set -e
	if [ "$gv_rc" -ne 0 ]; then
		echo "check-govulncheck: govulncheck -format json exited $gv_rc (expected 0 -- JSON mode exits 0 regardless of findings, so a nonzero exit here is a tool or build problem, not a vulnerability verdict)" >&2
		cat "$work/govulncheck.stderr" >&2
		exit 1
	fi
fi

# One row per reachable (osv, first-seen) pair: osv TAB module TAB version TAB
# fixed_version TAB chain. "reachable" per the header above: trace length >1.
jq -r '
	select(.finding != null) | .finding |
	select((.trace | length) > 1) |
	[
		.osv,
		.trace[0].module,
		.trace[0].version,
		(.fixed_version // "N/A"),
		([.trace[] | (.function // .package // .module)] | reverse | join(" -> "))
	] | @tsv
' "$work/govulncheck.json" >"$work/reachable.tsv"

# Allowlist: column 1 of every fragment, exact string match only.
allow_file="$work/allow.txt"
: >"$allow_file"
if [ -d "$exceptions_dir" ]; then
	for f in "$exceptions_dir"/*.tsv; do
		[ -e "$f" ] || continue
		cut -f1 "$f" >>"$allow_file"
	done
fi

reachable_ids=$(cut -f1 "$work/reachable.tsv" | sort -u)
blocking=0
allowed_seen=""
if [ -n "$reachable_ids" ]; then
	while IFS= read -r id; do
		[ -n "$id" ] || continue
		if grep -qxF "$id" "$allow_file" 2>/dev/null; then
			allowed_seen="$allowed_seen $id"
			echo "check-govulncheck: ALLOWED $id (docs/govulncheck-exceptions.d/$id.tsv) --" >&2
			awk -F'\t' -v id="$id" '$1==id {printf "  module %s@%s, fixed_version=%s\n  %s\n", $2, $3, $4, $5}' "$work/reachable.tsv" | head -2 >&2
		else
			blocking=1
			echo "check-govulncheck: BLOCKING $id -- reachable, no row in docs/govulncheck-exceptions.d/ (see https://pkg.go.dev/vuln/$id)" >&2
			awk -F'\t' -v id="$id" '$1==id {printf "  module %s@%s, fixed_version=%s\n  %s\n", $2, $3, $4, $5}' "$work/reachable.tsv" | head -2 >&2
		fi
	done <<<"$reachable_ids"
fi

if [ "$blocking" -ne 0 ]; then
	echo "check-govulncheck: one or more reachable findings are not allowlisted -- see docs/govulncheck-exceptions.d/README.md to add a reviewed, dated row, or bump the dependency past fixed_version" >&2
	exit 1
fi

count=$(wc -l <"$work/reachable.tsv" | tr -d ' ')
echo "check-govulncheck: clean ($count reachable trace(s) total, allowlisted IDs:${allowed_seen:- none})" >&2
exit 0
