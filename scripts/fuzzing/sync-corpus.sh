#!/usr/bin/env bash
# Copies any new/changed crash reproducers under **every** testdata/fuzz/ in the
# main fuzzing clone into a SEPARATE git worktree checked out on the fuzz-corpus
# branch, then commits + pushes from there.
#
# Deliberately does not touch git branches in $KEYORIX_REPO itself — that clone
# stays on main throughout a run (run-rotation.sh resets it to origin/main), so
# results land on a distinct branch without ever disturbing the checkout the
# fuzzer is actively running against.
#
# Safe to call after every target regardless of outcome: a no-op when there is
# nothing new under any testdata/fuzz/.
set -euo pipefail

FUNC="${1:?fuzz func name}"
STATUS="${2:-0}"

: "${KEYORIX_REPO:?}"
: "${FUZZ_CORPUS_WORKTREE:?set FUZZ_CORPUS_WORKTREE to a git worktree checked out on the fuzz-corpus branch}"
: "${FUZZ_CORPUS_BRANCH:=fuzz-corpus}"

# Go's fuzz engine writes a crash reproducer into the *package's own*
# testdata/fuzz/<FuncName>/ — e.g. internal/notary/testdata/fuzz/FuzzVerifyReceipt/
# — NOT a single repo-root testdata/fuzz/. The previous version of this script
# rsynced only "$KEYORIX_REPO/testdata/fuzz/" (the repo root), which for this
# module never exists, so every crash reproducer this rig ever found was
# silently dropped: the fuzz-corpus branch sat at an empty commit for months and
# notify-on-crash.sh then classified every real crash as "infra failure, no
# reproducer on the branch". That is the root cause of keyorixhq/keyorix#1243
# and #1248 being wrongly closed. Discover the dirs across the whole tree
# instead (matching CI/discover, and dashdiag's sibling script which already
# globs '*/testdata/fuzz/*').
#
# Non-crashing "new interesting" corpus stays in the local build cache
# ($GOCACHE/fuzz) and is never written into the tree, so anything found here is
# by construction a real failing input worth a human's attention.
cd "$KEYORIX_REPO"
mapfile -t fuzz_dirs < <(find . -type d -path '*/testdata/fuzz' -not -path './.git/*' -printf '%P\n' | sort)
if [[ ${#fuzz_dirs[@]} -eq 0 ]]; then
  exit 0 # no target has produced a reproducer yet — the normal common case
fi

mkdir -p "$FUZZ_CORPUS_WORKTREE"
# -R/--relative recreates each source's full relative path under the worktree,
# so internal/notary/testdata/fuzz/... lands at the same path on the branch and,
# once merged to main, becomes seed corpus for that package. --update never
# overwrites a corpus file already on the branch with an older copy.
rsync -aR --update "${fuzz_dirs[@]}" "$FUZZ_CORPUS_WORKTREE/"

cd "$FUZZ_CORPUS_WORKTREE"
git add -- '*/testdata/fuzz/*' 'testdata/fuzz/*' 2>/dev/null || git add -A

if git diff --cached --quiet; then
  exit 0
fi

label="new corpus"
[[ "$STATUS" -ne 0 ]] && label="CRASH found"

git commit -m "fuzz($FUNC): $label $(date -u +%FT%TZ)" --quiet
git push origin "$FUZZ_CORPUS_BRANCH" --quiet
