#!/usr/bin/env bash
# scripts/pre-push-hook-test.sh -- offline self-check for the merge-queue guards
# in .githooks/pre-push (PREPUSH-MQ-GUARDS-1): the fuzz-targets check and the
# coverage-ledger check.
#
# Builds a throwaway git repository under a mktemp -d directory (a tiny Go
# module plus the real gen-targets-conf.sh, check-review-coverage.sh and hook)
# and checks that the hook
#   - stays silent and exits 0 for a diff that touches neither (a no-op);
#   - refuses a new FuzzXxx function with no targets.d entry, and a removed
#     function whose entry is left behind, and accepts them once consistent;
#   - refuses a stale targets.conf after a targets.d edit;
#   - refuses a new Go package with no ledger row and accepts it with a
#     docs/review-coverage.d fragment; ignores a new package in a nested module;
#   - still runs both checks when golangci-lint is not installed, and skips the
#     ledger check (exit 0, message on stderr) when go is not installed.
#
# Usage: scripts/pre-push-hook-test.sh   (from anywhere)
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd "$here/.." && pwd)

unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_COMMON_DIR
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
# The fixture is its own module: an inherited GOWORK would load this repo's.
export GOWORK=off GOTOOLCHAIN=local
export GIT_AUTHOR_NAME=Tester GIT_AUTHOR_EMAIL=tester@example.invalid
export GIT_COMMITTER_NAME=Tester GIT_COMMITTER_EMAIL=tester@example.invalid

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
bad() {
  fail=$((fail + 1))
  echo "FAIL: $*" >&2
}

# Tools the hook needs, linked into a PATH of their own so a case can leave
# golangci-lint (never linked) or go out.
bin_full="$tmp/bin-full"
bin_nogo="$tmp/bin-nogo"
mkdir -p "$bin_full" "$bin_nogo"
for t in sh bash git grep sed sort comm cut cat mktemp rm dirname xargs date head wc tr uniq awk ls env cp mkdir diff; do
  p=$(command -v "$t" || true)
  [ -n "$p" ] || continue
  ln -s "$p" "$bin_full/$t"
  ln -s "$p" "$bin_nogo/$t"
done
# The real toolchain binary: `go` on PATH may be a wrapper script that needs
# the rest of the caller's PATH.
real_go="$(go env GOROOT)/bin/go"
[ -x "$real_go" ] || real_go=$(command -v go)
ln -s "$real_go" "$bin_full/go"

# new_fixture NAME: a repo whose main has one package (pkg/a, one fuzz target,
# one ledger row) and whose HEAD is a branch off it. Prints the directory.
new_fixture() {
  local d="$tmp/$1"
  mkdir -p "$d/.githooks" "$d/scripts/fuzzing/targets.d" "$d/docs/review-coverage.d" "$d/pkg/a"
  cp "$repo/.githooks/pre-push" "$d/.githooks/pre-push"
  cp "$repo/scripts/fuzzing/gen-targets-conf.sh" "$d/scripts/fuzzing/"
  cp "$repo/scripts/check-review-coverage.sh" "$d/scripts/"
  printf '# header\n' >"$d/scripts/fuzzing/targets.d/HEADER.txt"
  printf 'pkg/a|FuzzA|1h\n' >"$d/scripts/fuzzing/targets.d/pkg-a__FuzzA.conf"
  printf 'module github.com/keyorixhq/keyorix\n\ngo 1.21\n' >"$d/go.mod"
  printf 'package a\n' >"$d/pkg/a/a.go"
  printf 'package a\n\nimport "testing"\n\nfunc FuzzA(f *testing.F) {}\n' >"$d/pkg/a/a_test.go"
  printf 'pkg/a\tnone\t-\t-\tpending\n' >"$d/docs/review-coverage.tsv"
  (
    cd "$d"
    bash scripts/fuzzing/gen-targets-conf.sh >/dev/null
    git init -q -b main .
    git add -A
    git commit -q -m base
    git checkout -q -b feature
  )
  printf '%s\n' "$d"
}

commit_all() {
  (cd "$1" && git add -A && git commit -q -m "$2")
}

# run_hook DIR PATHDIR: sets rc and out.
run_hook() {
  rc=0
  out=$(cd "$1" && PATH="$2" sh .githooks/pre-push 2>&1) || rc=$?
}

# check DESC WANT_RC GREP_PATTERN [ABSENT_PATTERN]
check() {
  local desc=$1 want=$2 pat=$3 absent=${4:-}
  if [ "$rc" -ne "$want" ]; then
    bad "$desc: exit $rc, want $want; output:"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    return
  fi
  if [ -n "$pat" ] && ! printf '%s\n' "$out" | grep -qE "$pat"; then
    bad "$desc: output lacks /$pat/; output:"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    return
  fi
  if [ -n "$absent" ] && printf '%s\n' "$out" | grep -qE "$absent"; then
    bad "$desc: output has /$absent/; output:"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    return
  fi
  pass=$((pass + 1))
}

# 1. no-op: a docs-only diff runs neither guard.
d=$(new_fixture noop)
echo hello >"$d/README.md"
commit_all "$d" docs
run_hook "$d" "$bin_full"
check "no-op diff" 0 "" "fuzz targets|coverage"

# 2. new FuzzXxx with no entry -> refused, with the fix hint.
d=$(new_fixture fuzz-missing)
printf 'package a\n\nimport "testing"\n\nfunc FuzzB(f *testing.F) {}\n' >"$d/pkg/a/b_test.go"
commit_all "$d" "add FuzzB"
run_hook "$d" "$bin_full"
check "FuzzB without a targets.d entry" 1 "pkg/a\|FuzzB" ""
check "FuzzB failure carries the fix hint" 1 "gen-targets-conf.sh"

# 3. same, with entry + regenerated targets.conf -> accepted.
printf 'pkg/a|FuzzB|1h\n' >"$d/scripts/fuzzing/targets.d/pkg-a__FuzzB.conf"
(cd "$d" && bash scripts/fuzzing/gen-targets-conf.sh >/dev/null)
commit_all "$d" "declare FuzzB"
run_hook "$d" "$bin_full"
check "FuzzB declared and targets.conf regenerated" 0 "fuzz targets OK"

# 4. entry added but targets.conf not regenerated -> refused.
d=$(new_fixture conf-stale)
printf 'pkg/a|FuzzA|2h\n' >"$d/scripts/fuzzing/targets.d/pkg-a__FuzzA.conf"
commit_all "$d" "edit target"
run_hook "$d" "$bin_full"
check "stale targets.conf" 1 "stale|fuzz targets check failed"

# 5. FuzzXxx removed, entry left -> refused as stale entry.
d=$(new_fixture fuzz-removed)
git -C "$d" rm -q pkg/a/a_test.go
commit_all "$d" "drop FuzzA"
run_hook "$d" "$bin_full"
check "removed FuzzA with its entry left behind" 1 "gone from the tree"

# 6. a FuzzXxx under testdata/ is ignored (go test ignores testdata).
d=$(new_fixture fuzz-testdata)
mkdir -p "$d/pkg/a/testdata/x"
printf 'package x\n\nimport "testing"\n\nfunc FuzzIgnored(f *testing.F) {}\n' >"$d/pkg/a/testdata/x/x_test.go"
commit_all "$d" "testdata fuzz"
run_hook "$d" "$bin_full"
check "FuzzXxx under testdata" 0 "fuzz targets OK"

# 7. new package with no ledger row -> refused; fragment -> accepted.
d=$(new_fixture ledger-new)
mkdir -p "$d/pkg/b"
printf 'package b\n' >"$d/pkg/b/b.go"
commit_all "$d" "add pkg/b"
run_hook "$d" "$bin_full"
check "new package without a ledger row" 1 "pkg/b"
check "new package failure carries the fix hint" 1 "docs/review-coverage.d"
printf 'pkg/b\tnone\t-\t-\tpending\n' >"$d/docs/review-coverage.d/pkg__b.tsv"
commit_all "$d" "ledger row"
run_hook "$d" "$bin_full"
check "new package with a ledger fragment" 0 "coverage ledger OK .*2 package\(s\) covered"

# 8. new package inside a nested module is not the root ledger's business.
d=$(new_fixture ledger-nested)
mkdir -p "$d/sub/inner"
printf 'module example.invalid/sub\n\ngo 1.21\n' >"$d/sub/go.mod"
printf 'package inner\n' >"$d/sub/inner/i.go"
git -C "$d" add -A
git -C "$d" commit -q -m "nested module"
git -C "$d" checkout -q main
git -C "$d" merge -q --ff-only feature
git -C "$d" checkout -q -b feature2
mkdir -p "$d/sub/inner2"
printf 'package inner2\n' >"$d/sub/inner2/i.go"
commit_all "$d" "package in nested module"
run_hook "$d" "$bin_full"
check "new package in a nested module" 0 "" "coverage ledger"

# 9. golangci-lint is absent from both PATHs: the guards still run.
d=$(new_fixture no-golangci)
mkdir -p "$d/pkg/b"
printf 'package b\n' >"$d/pkg/b/b.go"
commit_all "$d" "add pkg/b"
run_hook "$d" "$bin_full"
check "ledger check runs without golangci-lint" 1 "golangci-lint not found.*skipping local lint" ""
check "ledger check still refuses without golangci-lint" 1 "pkg/b"

# 10. go absent: the ledger check is skipped quietly (exit 0, message).
run_hook "$d" "$bin_nogo"
check "ledger check skipped without go" 0 "skipping the coverage-ledger check" "coverage-ledger check failed"

echo "pre-push-hook-test: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
