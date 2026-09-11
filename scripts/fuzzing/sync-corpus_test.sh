#!/usr/bin/env bash
# Tests for sync-corpus.sh — specifically that it picks up crash reproducers
# from a package's own testdata/fuzz/ (internal/<pkg>/testdata/fuzz/...), the
# path the previous version silently ignored. No network: pushes go to a local
# bare repo standing in for origin.
#
# check() evals a single-quoted expression, so its variables expand at call
# time — which SC2016/SC2034 cannot see.
# shellcheck disable=SC2016,SC2034
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fails=0
check() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fails=$((fails + 1)); fi; }

# A bare "origin" for the fuzz-corpus branch, a fuzzing clone (KEYORIX_REPO),
# and a worktree checked out on fuzz-corpus.
git init -q --bare "$WORK/origin.git"
git init -q -b main "$WORK/repo"
(
  cd "$WORK/repo"
  git config user.email t@t
  git config user.name t
  git remote add origin "$WORK/origin.git"
  git commit -q --allow-empty -m init
  git branch fuzz-corpus
  git push -q origin main fuzz-corpus
  git worktree add -q "$WORK/corpus" fuzz-corpus
)

export KEYORIX_REPO="$WORK/repo"
export FUZZ_CORPUS_WORKTREE="$WORK/corpus"
export FUZZ_CORPUS_BRANCH=fuzz-corpus
corpus_head() { git -C "$WORK/corpus" rev-parse HEAD; }

# 1. Nothing under any testdata/fuzz/ -> no-op, no new commit.
before="$(corpus_head)"
bash "$HERE/sync-corpus.sh" FuzzNothing 0
check "no reproducer anywhere is a no-op" '[[ "$(corpus_head)" == "$before" ]]'

# 2. A crasher in a PACKAGE's testdata/fuzz/ (the case the old script dropped).
mkdir -p "$WORK/repo/internal/notary/testdata/fuzz/FuzzVerifyReceipt"
printf 'go test fuzz v1\n[]byte("boom")\n' \
  >"$WORK/repo/internal/notary/testdata/fuzz/FuzzVerifyReceipt/deadbeef"
bash "$HERE/sync-corpus.sh" FuzzVerifyReceipt 1
check "package-level reproducer is committed" '[[ "$(corpus_head)" != "$before" ]]'
check "reproducer landed at its package path on the branch" '[[ -f "$WORK/corpus/internal/notary/testdata/fuzz/FuzzVerifyReceipt/deadbeef" ]]'
check "commit message marks a crash" 'git -C "$WORK/corpus" log -1 --format=%s | grep -q "CRASH found"'
check "reproducer was pushed to origin" 'git -C "$WORK/origin.git" ls-tree -r --name-only fuzz-corpus | grep -q "internal/notary/testdata/fuzz/FuzzVerifyReceipt/deadbeef"'

# 3. Re-running with no new files is a no-op (idempotent).
after="$(corpus_head)"
bash "$HERE/sync-corpus.sh" FuzzVerifyReceipt 1
check "second run with nothing new is a no-op" '[[ "$(corpus_head)" == "$after" ]]'

# 4. A second package's crasher is also picked up (glob is tree-wide).
mkdir -p "$WORK/repo/internal/saml/testdata/fuzz/FuzzSAMLMetadata"
printf 'go test fuzz v1\n[]byte("x")\n' \
  >"$WORK/repo/internal/saml/testdata/fuzz/FuzzSAMLMetadata/cafe"
bash "$HERE/sync-corpus.sh" FuzzSAMLMetadata 1
check "a different package's reproducer is also synced" '[[ -f "$WORK/corpus/internal/saml/testdata/fuzz/FuzzSAMLMetadata/cafe" ]]'

echo
if [[ "$fails" -ne 0 ]]; then
  echo "$fails check(s) failed"
  exit 1
fi
echo "all checks passed"
