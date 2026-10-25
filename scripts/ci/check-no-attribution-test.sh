#!/usr/bin/env bash
# scripts/ci/check-no-attribution-test.sh -- offline tests for
# scripts/ci/check-no-attribution.sh and .githooks/commit-msg
# (CI-NO-ATTRIBUTION-1).
#
# Builds throwaway git repositories under a mktemp -d directory and checks:
#   - a clean range, clean PR title and clean PR body pass;
#   - each pattern, in any letter case, fails in a commit message (head, a
#     commit in the middle of the range, a merge commit), in the PR title and
#     in the PR body;
#   - the exact lines the Claude Code harness appends (co-author trailer,
#     session trailer, the bracketed and the plain footer, the bare link) fail;
#   - near misses (another co-author, the word Claude alone) pass;
#   - a PR body with CRLF or CR-only line breaks fails on the right line and
#     no carriage return reaches the output;
#   - a commit ADDING the real rule text (CLAUDE.md, web/CLAUDE.md,
#     docs/adr-081-github-flow-branching.md) under a clean message passes,
#     while the same text used as a message fails (so the files really carry
#     the patterns and the pass is not vacuous);
#   - --message-file ignores comment lines and the `git commit -v` diff;
#   - an unknown commit or a missing merge base exits 2 (fail closed);
#   - the commit-msg hook rejects every pattern in a real `git commit` and
#     lets a clean one through.
# The workflow job runs this before the check itself; scripts/ci
# TestNoAttributionCheckScript runs it in the Go suite.
#
# Usage: scripts/ci/check-no-attribution-test.sh   (from anywhere)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/../.." && pwd)
script="$here/check-no-attribution.sh"
hook="$repo/.githooks/commit-msg"

# Outer git state (when run from a hook or with an exported GIT_DIR) must not
# leak into the throwaway repositories.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
export GIT_AUTHOR_NAME=Tester GIT_AUTHOR_EMAIL=tester@example.invalid
export GIT_COMMITTER_NAME=Tester GIT_COMMITTER_EMAIL=tester@example.invalid
unset PR_TITLE PR_BODY

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); }
bad() {
  fail=$((fail + 1))
  echo "FAIL: $*" >&2
}

# expect STATUS DESCRIPTION CMD...: runs CMD, compares its exit status.
expect() {
  local want=$1 desc=$2 got=0 out
  shift 2
  out=$("$@" 2>&1) || got=$?
  if [ "$got" -eq "$want" ]; then
    ok
  else
    bad "$desc: exit $got, want $want; output:"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

# One sample per pattern, in a mixed letter case, as it really appears.
samples=(
  'Co-Authored-By: Claude Opus <noreply@example.invalid>'
  'co-authored-by:claude'
  'CO-AUTHORED-BY:   CLAUDE SONNET'
  'Claude-Session: 5cf9f1d6'
  'claude-session-id: abc'
  'Generated with [Claude Code](https://example.invalid)'
  'see https://Claude.AI/code for details'
  'Co-Authored-By: Someone <NoReply@Anthropic.com>'
  'Generated with Claude Code'
  'see https://Claude.com/claude-code'
  # The exact lines the Claude Code harness appends.
  'Co-Authored-By: Claude <noreply@anthropic.com>'
  'Claude-Session: https://claude.ai/code/session_x'
  '🤖 Generated with [Claude Code](https://claude.com/claude-code)'
  '🤖 Generated with Claude Code'
)
near_misses=(
  'Co-Authored-By: Jane Doe <jane@example.invalid>'
  'fix(docs): describe the Claude rule in CLAUDE.md'
  'generated with go generate'
  'anthropic.com/news was cited in a doc'
  'Signed-off-by: Tester <tester@example.invalid>'
  'generated with the openapi code generator'
  'claude.com is a domain, claude-code a word'
)

new_repo() {
  local d=$1
  git init -q -b main "$d"
  git -C "$d" config commit.gpgsign false
  git -C "$d" config core.hooksPath /dev/null
  git -C "$d" commit -q --allow-empty -m "root"
}

r="$tmp/range"
new_repo "$r"
base=$(git -C "$r" rev-parse HEAD)
git -C "$r" commit -q --allow-empty -m "feat: one" -m "Signed-off-by: Tester <tester@example.invalid>"
git -C "$r" commit -q --allow-empty -m "fix: two"
clean_head=$(git -C "$r" rev-parse HEAD)

# run_in DIR CMD...: CMD with DIR as the working directory.
run_in() { (cd "$1" && shift && "$@"); }
in_repo() { run_in "$r" "$@"; }

# --- clean input passes -------------------------------------------------------
expect 0 "clean range" in_repo bash "$script" "$base..$clean_head"
expect 0 "clean title and body" env PR_TITLE="ci: add a guard" PR_BODY=$'## Why\nBecause.\n\nSession: X' bash "$script"
expect 0 "clean range, title and body" env PR_TITLE="ci: add a guard" PR_BODY="body" bash -c "cd '$r' && bash '$script' '$base..$clean_head'"
for m in "${near_misses[@]}"; do
  expect 0 "near miss in title: $m" env PR_TITLE="$m" bash "$script"
  git -C "$r" checkout -q --detach "$clean_head"
  git -C "$r" commit -q --allow-empty -m "chore: near miss" -m "$m"
  expect 0 "near miss in commit: $m" in_repo bash "$script" "$base..HEAD"
done

# --- each pattern fails, wherever it is -----------------------------------------
for s in "${samples[@]}"; do
  expect 1 "title: $s" env PR_TITLE="x $s" bash "$script"
  expect 1 "body: $s" env PR_BODY=$'## Summary\nok\n\n'"$s" bash "$script"

  # In the head commit's trailer.
  git -C "$r" checkout -q --detach "$clean_head"
  git -C "$r" commit -q --allow-empty -m "feat: x" -m "$s"
  expect 1 "head commit: $s" in_repo bash "$script" "$base..HEAD"

  # In a commit in the middle of the range, followed by a clean one.
  git -C "$r" checkout -q --detach "$base"
  git -C "$r" commit -q --allow-empty -m "feat: middle" -m "$s"
  git -C "$r" commit -q --allow-empty -m "fix: clean on top"
  expect 1 "middle commit: $s" in_repo bash "$script" "$base..HEAD"

  # In a merge commit's message only (both parents clean).
  git -C "$r" checkout -q --detach "$clean_head"
  git -C "$r" branch -q -f side "$base"
  git -C "$r" checkout -q side
  git -C "$r" commit -q --allow-empty -m "feat: side"
  git -C "$r" checkout -q --detach "$clean_head"
  git -C "$r" merge -q --no-ff --allow-unrelated-histories -m "Merge side" -m "$s" side
  expect 1 "merge commit: $s" in_repo bash "$script" "$base..HEAD"
done

# A hit reports the commit and the line, labelled so untrusted text never
# starts an output line.
out=$(env PR_BODY=$'::error::x\n'"${samples[0]}" bash "$script" 2>&1 || true)
if printf '%s\n' "$out" | grep -q '^  PR body, line 2:Co-Authored-By: Claude' && ! printf '%s\n' "$out" | grep -q '^::'; then
  ok
else
  bad "hit output not labelled as expected:"$'\n'"$out"
fi

# A PR body as GitHub sends it, with CRLF line endings, ending with the footer
# the harness appends: it fails, the hit names the right line, and no carriage
# return reaches the output.
crlf_body=$'## Summary\r\n- fix the thing\r\n\r\n## Test plan\r\n- [x] tests pass\r\n\r\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\r\n'
expect 1 "CRLF body with the footer" env PR_BODY="$crlf_body" bash "$script"
out=$(env PR_BODY="$crlf_body" bash "$script" 2>&1 || true)
case "$out" in
  *$'\r'*) bad "carriage return in the hit output:"$'\n'"$out" ;;
  *) ok ;;
esac
if printf '%s\n' "$out" | grep -q '^  PR body, line 7:🤖 Generated with \[Claude Code\](https://claude.com/claude-code)$'; then
  ok
else
  bad "CRLF hit not reported as line 7 without the CR:"$'\n'"$out"
fi
expect 1 "CRLF body with the plain footer" env PR_BODY=$'## Summary\r\nok\r\n\r\n🤖 Generated with Claude Code\r\n' bash "$script"
cr_body=$'## Summary\rok\rCo-Authored-By: Claude <noreply@anthropic.com>\r'
expect 1 "CR-only line breaks" env PR_BODY="$cr_body" bash "$script"
out=$(env PR_BODY="$cr_body" bash "$script" 2>&1 || true)
if printf '%s\n' "$out" | grep -q '^  PR body, line 3:Co-Authored-By: Claude <noreply@anthropic.com>$' && [ "${out%%$'\r'*}" = "$out" ]; then
  ok
else
  bad "CR-only hit not reported as line 3 without the CR:"$'\n'"$out"
fi
expect 0 "clean CRLF body" env PR_BODY=$'## Summary\r\n- fix\r\n\r\nSession: X\r\n' bash "$script"

# --- the rule text in the repo is file content, not a message -------------------
rule_files=(CLAUDE.md web/CLAUDE.md docs/adr-081-github-flow-branching.md)
d="$tmp/rules"
new_repo "$d"
rbase=$(git -C "$d" rev-parse HEAD)
for f in "${rule_files[@]}"; do
  mkdir -p "$d/$(dirname "$f")"
  cp "$repo/$f" "$d/$f"
  git -C "$d" add "$f"
  git -C "$d" commit -q -m "docs: update $f"
  expect 0 "commit adding $f" run_in "$d" bash "$script" "$rbase..HEAD"
  # Not vacuous: the file does carry a pattern, so as a message it fails.
  expect 1 "$f as a message" bash "$script" --message-file "$repo/$f"
done

# --- --message-file -------------------------------------------------------------
mf="$tmp/msg"
printf 'feat: x\n\nSigned-off-by: Tester <tester@example.invalid>\n' >"$mf"
expect 0 "clean message file" bash "$script" --message-file "$mf"
for s in "${samples[@]}"; do
  printf 'feat: x\n\n%s\n' "$s" >"$mf"
  expect 1 "message file: $s" bash "$script" --message-file "$mf"
  printf 'feat: x\n\n# %s\n' "$s" >"$mf"
  expect 0 "comment line: $s" bash "$script" --message-file "$mf"
  printf 'feat: x\n# ------------------------ >8 ------------------------\n+%s\n' "$s" >"$mf"
  expect 0 "below scissors: $s" bash "$script" --message-file "$mf"
done

# --- usage and unreadable ranges fail closed ------------------------------------
expect 2 "no input" bash "$script"
expect 2 "unknown option" bash "$script" --nope
expect 2 "not a range" bash "$script" HEAD
expect 2 "missing message file" bash "$script" --message-file "$tmp/none"
expect 2 "unknown commit" in_repo bash "$script" "$base..0123456789abcdef0123456789abcdef01234567"
u="$tmp/unrelated"
new_repo "$u"
git -C "$r" fetch -q "$u" main:unrelated
expect 2 "no merge base" in_repo bash "$script" "$base..unrelated"
if [ "$(bash "$script" --patterns | grep -c .)" -eq 6 ]; then ok; else bad "--patterns does not list 6 patterns"; fi

# --- the commit-msg hook in a real commit ---------------------------------------
h="$tmp/hooked"
new_repo "$h"
mkdir -p "$h/scripts/ci" "$h/.githooks"
cp "$script" "$h/scripts/ci/"
cp "$hook" "$h/.githooks/"
git -C "$h" config core.hooksPath .githooks
for s in "${samples[@]}"; do
  expect 1 "hook rejects: $s" git -C "$h" commit -q --allow-empty -m "feat: x" -m "$s"
done
expect 0 "hook accepts a clean commit" git -C "$h" commit -q --allow-empty -m "feat: x" -m "Signed-off-by: Tester <tester@example.invalid>"
if [ "$(git -C "$h" rev-list --count HEAD)" -eq 2 ]; then ok; else bad "hook let a rejected commit through"; fi
rm "$h/scripts/ci/check-no-attribution.sh"
expect 1 "hook fails closed without the script" git -C "$h" commit -q --allow-empty -m "feat: y"

echo "check-no-attribution-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
