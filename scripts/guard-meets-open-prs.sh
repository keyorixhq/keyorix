#!/usr/bin/env bash
# guard-meets-open-prs.sh -- docs/guard-rollout-contract.md rule 2: before a
# new or widened repo-wide guard merges, run it over main AND over the open
# PRs it will meet, so a guard that is green alone but red against another
# PR's change is found before it stops the merge queue.
#
# It builds, without touching the working tree or any branch, the tree of
# HEAD (this branch) merged with the latest origin/main, and that tree merged
# with each PR's head (git merge-tree: the same three-way merge the queue
# makes; GitHub's refs/pull/N/merge is often computed against an older main).
# It exports each tree and runs the guard with KEYORIX_GUARD_ROLLOUT=enforce
# (a report-only guard must still show what it would fail). Paste the table
# into the introducing PR's body.
#
# Usage: scripts/guard-meets-open-prs.sh -p ./pkg -r 'TestRegex' [-n N] [PR...]
#   -p  Go package of the guard (run from the repository root)
#   -r  go test -run regex
#   -n  with no PR numbers: the N most recently updated open PRs (default 5;
#       needs gh). In a sandboxed session pass the numbers instead (kgh pr list).
#   PR  a PR number, or a local branch/commit (e.g. to prove the run goes red).
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

echo "guard-meets-open-prs: fetching origin/main and ${#prs[@]} PR head(s)" >&2
git fetch -q origin main
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# merged <commit> <commit>: a commit object (no ref) for their three-way
# merge, or nothing on a textual conflict.
merged() {
	local tree
	tree=$(git merge-tree --write-tree "$1" "$2" 2>/dev/null) || return 1
	git commit-tree "$tree" -p "$1" -p "$2" -m "guard-meets-open-prs scratch merge"
}
mainx=$(merged HEAD origin/main) || { echo "guard-meets-open-prs: HEAD conflicts with origin/main; merge main first" >&2; exit 2; }

fails=0
printf '| target | tree | result | detail |\n|---|---|---|---|\n' >"$work/table.md"
run_one() { # run_one <label> <commit>
	local label=$1 ref=$2 dir="$work/t" sha detail rc=0
	sha=$(git rev-parse --short=9 "$ref^{tree}")
	rm -rf "$dir"
	mkdir -p "$dir"
	git archive "$ref" | tar -x -C "$dir"
	echo "guard-meets-open-prs: $label (tree $sha): go test -run '$rx' $pkg" >&2
	(cd "$dir" && KEYORIX_GUARD_ROLLOUT=enforce GOFLAGS="${GOFLAGS//-trimpath/}" go test -count=1 -run "$rx" "$pkg" >"$work/out.log" 2>&1) || rc=$?
	if [ "$rc" -eq 0 ]; then
		printf '| %s | %s | PASS | |\n' "$label" "$sha" >>"$work/table.md"
	else
		fails=$((fails + 1))
		detail=$(grep -E -- '--- FAIL|_test\.go:[0-9]+' "$work/out.log" | grep -v 'guard rollout:' | head -3 | tr '\n|' ' /' | cut -c1-300)
		printf '| %s | %s | FAIL | %s |\n' "$label" "$sha" "$detail" >>"$work/table.md"
	fi
}

run_one "HEAD + origin/main" "$mainx"
for p in "${prs[@]}"; do
	if ! [[ "$p" =~ ^[0-9]+$ ]]; then # a local ref (calibration, or a PR not pushed yet)
		git update-ref "refs/guard-check/$p" "$(git rev-parse --verify "$p^{commit}")"
	elif ! git fetch -q origin "+refs/pull/$p/head:refs/guard-check/$p" 2>/dev/null; then
		printf '| #%s | - | NO HEAD | cannot fetch refs/pull/%s/head |\n' "$p" "$p" >>"$work/table.md"
		continue
	fi
	if c=$(merged "$mainx" "refs/guard-check/$p"); then
		label="+ $p"
		[[ "$p" =~ ^[0-9]+$ ]] && label="+ #$p"
		run_one "$label" "$c"
	elif merged origin/main "refs/guard-check/$p" >/dev/null; then
		printf '| + #%s | - | CONFLICT | conflicts with THIS branch: resolve before merging the guard |\n' "$p" >>"$work/table.md"
		fails=$((fails + 1))
	else
		printf '| + #%s | - | SKIPPED | conflicts with origin/main itself (not with this branch); it cannot enter the queue as it is |\n' "$p" >>"$work/table.md"
	fi
	git update-ref -d "refs/guard-check/$p"
done
cat "$work/table.md"
if [ "$fails" -gt 0 ]; then
	echo "guard-meets-open-prs: the guard fails on $fails target(s); name those PRs in the introducing PR and fix or warn them before it merges" >&2
	exit 1
fi
echo "guard-meets-open-prs: green on every target" >&2
