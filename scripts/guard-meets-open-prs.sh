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
#   -n  with no PR numbers: the N most recently updated open PRs (default 5).
#       Listed with $KEYORIX_GH (default gh); if that is missing or refuses and
#       kgh is on PATH, with `kgh pr list`. Neither works: exit 2 naming both.
#       In a sandboxed session kgh may not run from inside this script (it
#       needs to be a standalone command): run `kgh pr list --state open
#       --limit N --search "sort:updated-desc" --json number -q '.[].number'`
#       yourself and pass the numbers.
#   PR  a PR number, or a local branch/commit (e.g. to prove the run goes red).
#   -L  list the PRs that would be tested and exit (no git, no tests).
#   --self-test  prove the gh / kgh / neither selection with fake binaries.
# Exit: 0 every target green, 1 the guard fails somewhere, 2 usage/setup error.
set -euo pipefail


# list_open_prs: write the open PR numbers (one per line) to $work/prs.txt.
# Tries $KEYORIX_GH (default gh) first; when it is missing or refuses (the
# session sandbox blocks raw gh) and kgh is on PATH, tries
# `kgh pr list ... --search "sort:updated-desc" --json number -q '.[].number'`
# (the same PR set as gh). Neither: exit 2 naming both.
# kgh must run as its own command (no pipe, no $(...)), so its output goes to a
# file. Inside the sandbox even a redirect can stop kgh from reading its token;
# then run the printed kgh command as a standalone step and pass the numbers.
list_open_prs() {
	local gh=${KEYORIX_GH:-gh} out=$work/prs.txt
	if command -v "$gh" >/dev/null 2>&1 &&
		"$gh" pr list --state open --limit "$n" --search "sort:updated-desc" --json number --jq '.[].number' >"$out" 2>/dev/null; then
		return 0
	fi
	if command -v kgh >/dev/null 2>&1; then
		echo "guard-meets-open-prs: '$gh' unavailable or refused; trying kgh" >&2
		if kgh pr list --state open --limit "$n" --search "sort:updated-desc" --json number -q '.[].number' >"$out" 2>/dev/null; then
			return 0
		fi
		echo "guard-meets-open-prs: kgh failed too (in a sandbox run it as its own command: kgh pr list --state open --limit $n --search \"sort:updated-desc\" --json number -q '.[].number') and pass the PR numbers as arguments" >&2
		exit 2
	fi
	echo "guard-meets-open-prs: cannot list open PRs: '$gh' is missing or refused, and kgh is not on PATH; pass the PR numbers as arguments" >&2
	exit 2
}

# --self-test: prove the gh / kgh / neither selection with fake binaries.
self_test() {
	local d fails=0 got
	d=$(mktemp -d "${TMPDIR:-/tmp}/gmop-test.XXXXXX")
	trap 'rm -rf "$d"' RETURN
	mkdir -p "$d/gh" "$d/kgh" "$d/both" "$d/none"
	# The working fakes answer only when asked for the most recently UPDATED
	# PRs (sort:updated-desc), so a lister that drops the flag goes red.
	printf '#!/bin/sh\ncase "$*" in *sort:updated-desc*) printf "11\\n12\\n" ;; *) exit 1 ;; esac\n' >"$d/gh/gh"
	printf '#!/bin/sh\nexit 1\n' >"$d/kgh/gh"
	printf '#!/bin/sh\ncase "$*" in *sort:updated-desc*) printf "21\\n22\\n" ;; *) exit 1 ;; esac\n' >"$d/kgh/kgh"
	printf '#!/bin/sh\nexit 1\n' >"$d/gh/kgh"
	printf '#!/bin/sh\nexit 1\n' >"$d/both/gh"
	printf '#!/bin/sh\nexit 1\n' >"$d/both/kgh"
	chmod +x "$d"/gh/* "$d"/kgh/* "$d"/both/*
	check() { # check <name> <want-rc> <want-out-regex> <path-dir>
		local rc=0
		got=$(TMPDIR="$d" PATH="$4:/usr/bin:/bin" KEYORIX_GH=gh "$BASH" "$0" -L -p x -r x 2>"$d/err.txt") || rc=$?
		if [ "$rc" -eq "$2" ] && printf '%s\n%s' "$got" "$(cat "$d/err.txt")" | grep -Eq -- "$3"; then
			echo "ok   $1"
		else
			echo "FAIL $1: rc=$rc out=[$got] err=[$(cat "$d/err.txt")]"
			fails=$((fails + 1))
		fi
	}
	check "gh works: used" 0 '^11$' "$d/gh"
	check "gh refuses, kgh works: used" 0 '^21$' "$d/kgh"
	check "neither: exit 2 naming gh and kgh" 2 "gh.*kgh|kgh.*gh" "$d/none"
	check "both refuse: exit 2, hint keeps sort:updated-desc" 2 "kgh pr list .*sort:updated-desc" "$d/both"
	[ "$fails" -eq 0 ]
}

pkg="" rx="" n=5 list_only=0
case "${1:-}" in
--self-test)
	self_test
	exit $?
	;;
esac
while getopts "p:r:n:L" o; do
	case "$o" in
	p) pkg="$OPTARG" ;;
	r) rx="$OPTARG" ;;
	n) n="$OPTARG" ;;
	L) list_only=1 ;;
	*) exit 2 ;;
	esac
done
shift $((OPTIND - 1))
[ -n "$pkg" ] && [ -n "$rx" ] || { echo "usage: $0 -p ./pkg -r 'TestRegex' [-n N] [PR...]  |  $0 --self-test" >&2; exit 2; }
prs=("$@")
work=$(mktemp -d "${TMPDIR:-/tmp}/gmop.XXXXXX")
trap 'rm -rf "$work"' EXIT
if [ "${#prs[@]}" -eq 0 ]; then
	echo "guard-meets-open-prs: listing the $n most recently updated open PRs" >&2
	list_open_prs
	mapfile -t prs <"$work/prs.txt"
fi
if [ "$list_only" -eq 1 ]; then
	printf '%s\n' "${prs[@]}"
	exit 0
fi

echo "guard-meets-open-prs: fetching origin/main and ${#prs[@]} PR head(s)" >&2
git fetch -q origin main
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
