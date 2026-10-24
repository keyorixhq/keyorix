#!/usr/bin/env bash
# scripts/ci/check-no-attribution.sh -- fail when a commit message, the PR title
# or the PR body carries AI-assistant attribution (CI-NO-ATTRIBUTION-1).
#
# Attribution trailers and footers kept landing on main although CLAUDE.md,
# web/CLAUDE.md and docs/adr-081 forbid them: the rule was text, and a session
# harness that appends the lines by default wins over text. This makes it a
# check. The patterns (case-insensitive, matched anywhere in a line) are the
# PATTERNS array below; `--patterns` prints them.
#
# What is checked is only what ends up in git history or on the PR page: commit
# messages (merge commits included, since a merge commit's message lands on
# main too), the PR title and the PR body. File contents are never checked, so
# the rule text in CLAUDE.md, web/CLAUDE.md and docs/adr-081 does not trip it.
#
# Usage (from anywhere inside the repository):
#   check-no-attribution.sh BASE..HEAD           every commit in the range
#   PR_TITLE=... PR_BODY=... check-no-attribution.sh [BASE..HEAD]
#                                                 also the PR title and body
#   check-no-attribution.sh --message-file FILE   one commit message as git
#                                                 will store it (comment lines
#                                                 and the `git commit -v` diff
#                                                 below the scissors line are
#                                                 dropped); .githooks/commit-msg
#   check-no-attribution.sh --patterns            print the patterns
# Exit status: 0 clean, 1 attribution found, 2 usage error or a range that
# cannot be read (unknown commit, or a shallow clone without the merge base:
# fail closed rather than check a partial range).
#
# Callers: .github/workflows/no-attribution.yml (job no-attribution, on
# pull_request and merge_group) and .githooks/commit-msg. Tests:
# scripts/ci/check-no-attribution-test.sh. Portable to macOS's bash 3.2, since
# the commit-msg hook runs it on contributors' machines.
set -euo pipefail

PATTERNS=(
  'co-authored-by:[[:space:]]*claude'
  'claude-session'
  'generated with \[claude'
  'claude\.ai/code'
  'noreply@anthropic\.com'
)

usage() {
  sed -n '/^# Usage/,/^# Exit status/p' "$0" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

grep_args=()
for p in "${PATTERNS[@]}"; do
  grep_args+=(-e "$p")
done

found=0

# check LABEL TEXT: reports every line of TEXT matching a pattern. It runs in
# this shell, never as a pipeline stage, so `found` survives (a `| check` would
# set it in a subshell and pass every hit). The matched line is printed after a
# label, so a line of untrusted PR text can never start an output line (a
# GitHub Actions workflow command must).
check() {
  local label=$1 hits
  hits=$(printf '%s\n' "$2" | grep -inE "${grep_args[@]}" || true)
  [ -n "$hits" ] || return 0
  found=1
  while IFS= read -r hit; do
    printf '  %s, line %s\n' "$label" "$hit"
  done <<EOF
$hits
EOF
}

# strip_message FILE: the message git will store (default cleanup mode): no
# comment lines, nothing from the scissors line on.
strip_message() {
  local cc
  cc=$(git config core.commentChar 2>/dev/null || true)
  case "$cc" in '' | auto) cc='#' ;; esac
  awk -v cc="$cc" '
    $0 == cc " ------------------------ >8 ------------------------" { exit }
    index($0, cc) == 1 { next }
    { print }
  ' "$1"
}

report() {
  if [ "$found" -ne 0 ]; then
    echo "check-no-attribution: FAILED -- AI-assistant attribution found (above)." >&2
    echo "Remove those lines. Commits: git commit --amend (last commit) or git rebase -i <base> with reword." >&2
    echo "PR title/body: edit them on the PR page; this check re-runs on the edit." >&2
    echo "Rule: CLAUDE.md, CONTRIBUTING.md (DCO section). Patterns: scripts/ci/check-no-attribution.sh --patterns" >&2
    exit 1
  fi
  echo "check-no-attribution: ok, no attribution found"
}

range=""
case "${1:-}" in
  --patterns)
    printf '%s\n' "${PATTERNS[@]}"
    exit 0
    ;;
  --message-file)
    [ -n "${2:-}" ] && [ -f "$2" ] || usage
    check "commit message" "$(strip_message "$2")"
    report
    exit 0
    ;;
  -h | --help) usage ;;
  -*) usage ;;
  "") ;;
  *..*) range=$1 ;;
  *) usage ;;
esac

checked=""
if [ -n "$range" ]; then
  base=${range%%..*}
  head=${range#*..}
  [ -n "$base" ] && [ -n "$head" ] || usage
  for ref in "$base" "$head"; do
    if ! git rev-parse -q --verify "$ref^{commit}" >/dev/null; then
      echo "check-no-attribution: commit $ref is not in this clone (fetch it, or check out with full history)" >&2
      exit 2
    fi
  done
  if ! git merge-base "$base" "$head" >/dev/null; then
    echo "check-no-attribution: no merge base for $range in this clone (shallow checkout?); refusing to check a partial range" >&2
    exit 2
  fi
  shas=$(git rev-list "$base..$head")
  n=0
  for sha in $shas; do
    n=$((n + 1))
    check "commit ${sha:0:12}" "$(git log -1 --format=%B "$sha")"
  done
  echo "check-no-attribution: checked $n commit message(s) in $range"
  checked="commits"
fi
if [ -n "${PR_TITLE:-}" ]; then
  check "PR title" "$PR_TITLE"
  checked="$checked title"
fi
if [ -n "${PR_BODY:-}" ]; then
  check "PR body" "$PR_BODY"
  checked="$checked body"
fi
if [ -z "$checked" ]; then
  usage
fi
report
