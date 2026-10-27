#!/usr/bin/env bash
# Warn-only guard against growing a new shared append-only file.
#
# Flags an EXISTING non-generated text/data/doc file that a diff only appends to:
# more than LEDGER_MAX_APPEND added lines and zero removed lines. That is the shape
# of a shared ledger, the thing that made 19 of 152 PRs conflict while the
# fragment directories (changelog.d, docs/security-closures.d, INVARIANTS.d,
# targets.d) had zero conflicts in 139 merges. The fix it points at: add a
# per-item fragment file plus a build/reduce step instead of one more shared file.
#
# WARN-ONLY: always exits 0 for findings, prints a loud message (and a GitHub
# ::warning annotation when run in Actions). A heuristic this fuzzy must not block
# a merge: an append-only doc section or a genuinely new ledger is sometimes right.
# The point is that someone notices and chooses fragments deliberately. Once it has
# been observed for a while it can be made fail-closed by changing the final
# `exit 0` of the findings branch to `exit 1`.
#
# Scope, from the 30-day measurement in docs/design/architecture-growth-baseline.md
# (984 merged PRs, 2026-09-27..2026-10-27):
#   - only files the diff MODIFIES (a brand-new file is all additions by definition);
#   - only ledger-shaped extensions (md tsv txt conf json yaml yml csv toml): an
#     appended Go/TS/shell function is normal code growth, 1179 of 1705 append-only
#     modified files were Go and would drown the signal;
#   - the already-handled files are excluded (see is_known), as are generated files,
#     lock files and fragment directories (*.d/).
# LEDGER_MAX_APPEND=50 default: replayed over those 984 PRs with these exact rules it
# flags 16 PRs (1.6%, about one every two days). N=30 would flag 37 (3.8%), N=100
# only 3. The smallest append-only diff on a non-known file in that window is 1 line,
# so "the smallest observed" cannot be the threshold; 50 is the knee where the flag
# rate stops being daily noise.
#
#   scripts/ci/check-no-new-ledger.sh [BASE [HEAD]]   # default origin/main HEAD
#   scripts/ci/check-no-new-ledger.sh --self-test
#
# Env: LEDGER_MAX_APPEND (default 50).
set -uo pipefail

MAX="${LEDGER_MAX_APPEND:-50}"

# Already handled by the coordinator's auto-resolve on "merge main" (COMMON-RULES,
# HOT WIRING FILES / Changelog and closures).
is_known() {
  local p="$1" b="${1##*/}"
  case "$p" in
    CHANGELOG.md | docs/UPGRADING.md | docs/CONFIGURATION.md | scripts/fuzzing/targets.conf | \
      internal/config/testdata/config_surface_leaves.txt) return 0 ;;
  esac
  case "$b" in
    *.tsv | INVARIANTS.md | routes.json) return 0 ;;
  esac
  return 1
}

is_ledger_shaped() { # extension allowlist, minus generated/lock/fragment/golden paths
  local p="$1"
  case "$p" in
    *.d/* | */testdata/* | */golden/* | *-lock.json | *lock.yaml | *.lock | *generated* | *.gen.*) return 1 ;;
    *.md | *.txt | *.conf | *.json | *.yaml | *.yml | *.csv | *.toml) return 0 ;;
  esac
  return 1
}

scan() { # base head
  local base="$1" head="$2" found=0 checked=0 skipped=0 add del path
  if ! git rev-parse --verify -q "$base^{commit}" >/dev/null || ! git rev-parse --verify -q "$head^{commit}" >/dev/null; then
    echo "check-no-new-ledger: SKIPPED, cannot resolve $base or $head (fetch the base branch, e.g. git fetch origin main); no check was done" >&2
    return 0
  fi
  echo "check-no-new-ledger: $base...$head, warn when an existing file gains more than $MAX lines and loses none" >&2
  while IFS=$'\t' read -r add del path; do
    [ -n "$path" ] || continue
    [ "$add" != "-" ] || continue # binary
    if is_known "$path" || ! is_ledger_shaped "$path"; then
      skipped=$((skipped + 1))
      continue
    fi
    checked=$((checked + 1))
    if [ "$del" -eq 0 ] && [ "$add" -gt "$MAX" ]; then
      found=$((found + 1))
      echo "WARNING: $path gains $add lines and removes none (limit $MAX): the shape of a shared append-only ledger."
      echo "  What to do: if many PRs will append here, use per-item fragments plus a build/reduce step"
      echo "  (like changelog.d or docs/security-closures.d) instead. If this is one-off prose, ignore this."
      if [ -n "${GITHUB_ACTIONS:-}" ]; then
        echo "::warning file=$path::gains $add lines, removes none: append-only ledger shape; prefer per-item fragments (see docs/ARCHITECTURE.md, Growth ceilings)"
      fi
    fi
  done < <(git diff --numstat --no-renames --diff-filter=M "$base...$head")
  echo "check-no-new-ledger: $checked file(s) checked, $skipped skipped (known ledger, generated or code), $found warning(s); warn-only, exit 0" >&2
  return 0
}

self_test() {
  local d fail=0 out
  d="$(mktemp -d)" || { echo "self-test: mktemp failed" >&2; exit 1; }
  (
    set -e
    cd "$d"
    git init -q -b main .
    g() { git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false "$@"; }
    mkdir -p docs changelog.d
    seq 1 100 >docs/ledger.md
    seq 1 100 >docs/rewritten.md
    seq 1 100 >CHANGELOG.md
    seq 1 100 >docs/known.tsv
    seq 1 100 >code.go
    g add -A && g commit -q -m base
    git branch base
    seq 101 170 >>docs/ledger.md       # 70 added, 0 removed: WARN
    { seq 101 170; } >>docs/rewritten.md && sed -i.bak '1d' docs/rewritten.md && rm docs/rewritten.md.bak # 70 added, 1 removed: no warn
    seq 101 170 >>CHANGELOG.md         # known: no warn
    seq 101 170 >>docs/known.tsv       # known (*.tsv): no warn
    seq 101 170 >>code.go              # code: no warn
    seq 1 200 >docs/brand-new.md       # new file: no warn
    g add -A && g commit -q -m head
  ) || { echo "self-test: fixture setup failed" >&2; rm -rf "$d"; exit 1; }
  out="$(cd "$d" && scan base HEAD 2>/dev/null)"
  rc=$?
  grep -q "^WARNING: docs/ledger.md gains 70 lines" <<<"$out" || { echo "SELF-TEST FAIL: append-only file not flagged" >&2; fail=1; }
  [ "$(grep -c '^WARNING:' <<<"$out")" = 1 ] || { echo "SELF-TEST FAIL: expected exactly one warning, got: $out" >&2; fail=1; }
  [ "$rc" = 0 ] || { echo "SELF-TEST FAIL: warn-only guard returned $rc" >&2; fail=1; }
  rm -rf "$d"
  [ "$fail" = 0 ] && echo "check-no-new-ledger self-test OK: flags the append-only doc only; known, rewritten, code and new files pass; exit 0"
  exit "$fail"
}

case "${1:-}" in
  --self-test) self_test ;;
  -h | --help) sed -n '2,29p' "$0"; exit 0 ;;
  *) scan "${1:-origin/main}" "${2:-HEAD}" ;;
esac
exit 0
