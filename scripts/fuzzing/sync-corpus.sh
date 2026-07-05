#!/usr/bin/env bash
# Copies any new/changed files under testdata/fuzz/ from the main fuzzing
# clone into a SEPARATE git worktree checked out on the fuzz-corpus branch,
# then commits + pushes from there.
#
# Deliberately does not touch git branches in $KEYORIX_REPO itself — that
# clone stays on main throughout a run (run-rotation.sh resets it to
# origin/main once per cycle), so results land on a distinct branch without
# ever disturbing the checkout the fuzzer is actively running against.
#
# Safe to call after every rotation cycle regardless of outcome: it's a no-op
# when there's nothing new under testdata/fuzz/.
set -euo pipefail

FUNC="${1:?fuzz func name}"
STATUS="${2:-0}"

: "${KEYORIX_REPO:?}"
: "${FUZZ_CORPUS_WORKTREE:?set FUZZ_CORPUS_WORKTREE to a git worktree checked out on the fuzz-corpus branch}"
: "${FUZZ_CORPUS_BRANCH:=fuzz-corpus}"

mkdir -p "$FUZZ_CORPUS_WORKTREE/testdata/fuzz"
rsync -a --update "$KEYORIX_REPO/testdata/fuzz/" "$FUZZ_CORPUS_WORKTREE/testdata/fuzz/"

cd "$FUZZ_CORPUS_WORKTREE"
git add testdata/fuzz/

if git diff --cached --quiet; then
  exit 0
fi

label="new corpus"
[ "$STATUS" -ne 0 ] && label="CRASH found"

git commit -m "fuzz($FUNC): $label $(date -u +%FT%TZ)" --quiet
git push origin "$FUZZ_CORPUS_BRANCH" --quiet
