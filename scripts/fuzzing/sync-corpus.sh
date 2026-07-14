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

# Go's fuzz engine only ever creates testdata/fuzz/<FuncName>/ when a target
# actually CRASHES — never for ordinary coverage-expanding exploration (that
# non-crashing "new interesting" corpus stays in the local build cache,
# $GOCACHE/fuzz, and is never written into the source tree). So on any target
# that hasn't crashed yet, $KEYORIX_REPO/testdata/fuzz doesn't exist at all —
# this is the normal, expected common case, not an error. Without this guard,
# rsync's sender failed with "No such file or directory" (exit 23), and
# because run-rotation.sh calls this script with `set -e` active, that
# non-zero exit killed the ENTIRE run-rotation.sh process — which systemd's
# Restart=always then restarted from the top of targets.conf, re-fuzzing the
# FIRST target instead of advancing to the next one. Confirmed live: the rig
# had been stuck re-fuzzing target #1 in a 3-hour crash/restart loop since
# deployment, having never once reached a second target or a corpus commit.
[[ -d "$KEYORIX_REPO/testdata/fuzz" ]] || exit 0

rsync -a --update "$KEYORIX_REPO/testdata/fuzz/" "$FUZZ_CORPUS_WORKTREE/testdata/fuzz/"

cd "$FUZZ_CORPUS_WORKTREE"
git add testdata/fuzz/

if git diff --cached --quiet; then
  exit 0
fi

label="new corpus"
[[ "$STATUS" -ne 0 ]] && label="CRASH found"

git commit -m "fuzz($FUNC): $label $(date -u +%FT%TZ)" --quiet
git push origin "$FUZZ_CORPUS_BRANCH" --quiet
