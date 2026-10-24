#!/usr/bin/env bash
# guard-meets-open-prs.sh -- docs/guard-rollout-contract.md rule 2: before a
# new or widened repo-wide guard merges, run it over main AND over the open
# PRs it will meet, so a guard that is green alone but red against another
# PR's change is found before it stops the merge queue.
#
# For origin/main and for each PR's merge result (refs/pull/N/merge, GitHub's
# own "PR merged into main"), it exports the tree, applies this branch's
# change (origin/main...HEAD) on top, and runs the guard with
# KEYORIX_GUARD_ROLLOUT=enforce (a report-only guard must still show what it
# would fail). Paste the table into the introducing PR's body.
#
# Usage: scripts/guard-meets-open-prs.sh -p ./pkg -r 'TestRegex' [-n N] [PR...]
#   -p  Go package of the guard (run from the repository root)
#   -r  go test -run regex
#   -n  with no PR numbers: the N most recently updated open PRs (default 5;
#       needs gh). In a sandboxed session pass the numbers instead (kgh pr list).
# Exit: 0 every target green, 1 the guard fails somewhere, 2 usage/setup error.
set -euo pipefail

pkg="" rx="" n=5
while getopts "p:r:n:" o; do
	case "$o" in
	p) pkg="$OPTARG" ;;
	r) rx="$OPTARG" ;;
	n) n="$OPTARG" ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
[ -n "$pkg" ] && [ -n "$rx" ] || { echo "usage: $0 -p ./pkg -r 'TestRegex' [-n N] [PR...]" >&2; exit 2; }
prs=("$@")
if [ "${#prs[@]}" -eq 0 ]; then
	echo "guard-meets-open-prs: listing the $n most recently updated open PRs" >&2
	mapfile -t prs < <(gh pr list --state open --limit "$n" --search "sort:updated-desc" --json number --jq '.[].number')
fi

echo "guard-meets-open-prs: fetching origin/main and ${#prs[@]} merge ref(s)" >&2
git fetch -q origin main
base=$(git merge-base origin/main HEAD)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git diff --binary "$base" HEAD >"$work/guard.patch"
[ -s "$work/guard.patch" ] || echo "guard-meets-open-prs: HEAD adds nothing over origin/main; running the guard as it is on each target" >&2

fails=0
printf '| target | tree | result | detail |\n|---|---|---|---|\n' >"$work/table.md"
run_one() { # run_one <label> <ref>
	local label=$1 ref=$2 dir="$work/t" sha detail rc=0
	sha=$(git rev-parse --short=9 "$ref")
	rm -rf "$dir"
	mkdir -p "$dir"
	git archive "$ref" | tar -x -C "$dir"
	if [ -s "$work/guard.patch" ] && ! (cd "$dir" && git apply "$work/guard.patch" 2>"$work/apply.err"); then
		printf '| %s | %s | CONFLICT | this branch does not apply on it: %s |\n' "$label" "$sha" "$(head -1 "$work/apply.err" | tr '|' '/')" >>"$work/table.md"
		echo "guard-meets-open-prs: $label: this branch does not apply (textual conflict)" >&2
		return
	fi
	echo "guard-meets-open-prs: $label ($sha): go test -run '$rx' $pkg" >&2
	(cd "$dir" && KEYORIX_GUARD_ROLLOUT=enforce GOFLAGS="${GOFLAGS//-trimpath/}" go test -count=1 -run "$rx" "$pkg" >"$work/out.log" 2>&1) || rc=$?
	if [ "$rc" -eq 0 ]; then
		printf '| %s | %s | PASS | |\n' "$label" "$sha" >>"$work/table.md"
	else
		fails=$((fails + 1))
		detail=$(grep -E -- '--- FAIL|_test\.go:[0-9]+' "$work/out.log" | head -3 | tr '\n|' ' /' | cut -c1-300)
		printf '| %s | %s | FAIL | %s |\n' "$label" "$sha" "$detail" >>"$work/table.md"
		cp "$work/out.log" "$work/fail-${label//[^A-Za-z0-9]/_}.log"
	fi
}

run_one "origin/main" origin/main
for p in "${prs[@]}"; do
	if git fetch -q origin "+refs/pull/$p/merge:refs/guard-check/$p" 2>/dev/null; then
		run_one "#$p merged into main" "refs/guard-check/$p"
		git update-ref -d "refs/guard-check/$p"
	else
		printf '| #%s | - | NO MERGE REF | GitHub has no merge result (conflicting or closed) |\n' "$p" >>"$work/table.md"
	fi
done
cat "$work/table.md"
if [ "$fails" -gt 0 ]; then
	echo "guard-meets-open-prs: the guard fails on $fails target(s); name those PRs in the introducing PR and fix or warn them before it merges" >&2
	exit 1
fi
echo "guard-meets-open-prs: green on every target" >&2
