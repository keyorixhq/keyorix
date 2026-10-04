#!/usr/bin/env bash
# precheck-open-prs.sh -- find the PRs that will break INSIDE the merge queue,
# before they are enqueued.
#
# Why: a PR's own CI ran against the main it was branched from. The merge
# queue runs against today's main. Two PRs failed only in the queue for
# exactly that reason:
#   #2641  errcheck failure after an upstream signature change landed on main
#          (the PR's own CI was green; the rebased result was not lint-clean)
#   #2559  a Postgres-only test asserting log text that the PR's own refactor
#          changed (green in every non-PG job; only the PG leg saw it)
# This script reproduces "PR rebased onto current main" locally and runs the
# cheap checks that catch those two classes, for a list of PRs at once.
#
# Usage (run by the coordinator, from any checkout of this repo):
#   printf '2641\n2559\n' | scripts/ci/precheck-open-prs.sh [--quick]
#   scripts/ci/precheck-open-prs.sh < prs.txt
#   scripts/ci/precheck-open-prs.sh --self-test
#
#   stdin       PR numbers, one per line. Blank lines and '#' comments
#               (whole-line or trailing) are ignored.
#   --quick     test-compile only the changed packages instead of every
#               package of every affected module (see "test-compile" below).
#   --self-test build a throwaway origin+clone and prove each verdict red AND
#               green (BUILD FAIL, LINT FAIL, CONFLICT, OK). Needs no network.
#
# Environment:
#   GOLANGCI_LINT         golangci-lint binary to use (default: the one on
#                         PATH). Must be EXACTLY the version CI pins.
#   KEYORIX_TEST_PG_DSN   if set, also run the changed packages' tests with
#                         this DSN (the #2559 class). If unset: pg = not-run.
#   PRECHECK_LOG_DIR      where per-step logs go (default: a new mktemp dir,
#                         printed at the end and NOT deleted).
#   PRECHECK_REMOTE       remote to fetch from (default: origin).
#   PRECHECK_SELFTEST_HOLD  self-test only: seconds to pause after creating
#                         a worktree, so the Ctrl-C case has a window.
#
# Runtime: ~1.5 min per PR touching the root module on 4 cores with a warm
# Go build cache (3 real PRs: 3m18s), plus the PG test time if a DSN is set
# (#2559's changed packages: ~3 min). Shellcheck-clean (0.11.0).
#
# Per PR it prints one row: PR, rebase, build, vet, lint, test-compile, pg,
# overall. Exit status: 0 iff every PR is OK; 1 if any PR FAILs or CONFLICTs;
# 2 if none failed but some check could not run (INCOMPLETE -- e.g. lint
# skipped). A check that did not run is NEVER printed as ok:
#   ok        ran and passed
#   FAIL      ran and failed (log excerpt printed below the table)
#   ERROR     the tool itself failed to run (also counts as not-OK)
#   SKIP(..)  could not run (reason in parens); overall becomes INCOMPLETE
#   n/a       nothing to check (no Go package changed in that scope)
#   not-run   pg only: KEYORIX_TEST_PG_DSN unset (opt-in mode, by design)
#
# --- How each step works -------------------------------------------------
#
# rebase      `git fetch <remote> main` ONCE at start (pins one main SHA for
#             every PR in the run), then per PR: fetch refs/pull/<N>/head,
#             detach at it, `git rebase <main-sha>`. If the commit-by-commit
#             replay conflicts, the rebase is aborted and a plain 3-way merge
#             of the PR head into main is tried: this repo squash-merges, and
#             the queue's squash tree IS the 3-way merge result, so a branch
#             that merely merged main into itself mid-way (a common cause of
#             replay-only conflicts) is not a real conflict. Column shows
#             `ok` (rebased), `merge` (replay conflicted, 3-way merge clean --
#             checks then run on the merge result; overall still OK), or
#             CONFLICT (both conflict; nothing else runs for that PR).
#
# modules     This repo is several Go modules: . (root; go.work lists only
#             `use .`), cli/, migrate/, operator/ (each built in CI with
#             GOWORK=off and working-directory: <module>), devtools/* (not in
#             CI). Every go.mod in the tree is discovered (vendor/,
#             node_modules/, testdata/ excluded); every go command here runs
#             with GOWORK=off from the owning module's own directory --
#             identical to CI for the submodules, and equivalent for the root
#             because go.work contains nothing but `.`.
#             A changed file belongs to the module with the longest matching
#             directory prefix. "Affected modules" = modules with a changed
#             file, plus -- transitively -- every module whose go.mod has a
#             LOCAL `replace` pointing at an affected module (cli/ replaces
#             the root module with ../, so any root change also builds cli/).
#
# changed     `git diff --name-only <main-sha> HEAD` after the rebase/merge,
# packages    keep *.go files outside testdata/ and vendor/, take their
#             directories, keep those that still hold *.go files (a deleted
#             package has nothing to vet; importers of it are caught by
#             build). A changed go.mod/go.sum widens that module to ./...
#
# build       `go build ./...` in every affected module -- compile breakage
#             anywhere, including packages the PR never touched (#2641's
#             "main changed a signature" direction).
# vet         `go vet <changed pkgs>` per module (type-checks _test.go too).
# lint        golangci-lint on the changed packages, from the module's
#             directory, picking up the repo's root .golangci.yml exactly as
#             CI's golangci-lint-action does (CI sets no extra args). The
#             version CI pins is READ from .github/workflows/ci.yml
#             (GOLANGCI_LINT_VERSION) at run time; a binary of any other
#             version is SKIP(lint-version), not run, because a different
#             golangci-lint is a different set of checks. Missing binary:
#             SKIP(lint-missing). errcheck is enabled in .golangci.yml, which
#             is what catches #2641's class: the call site the PR added or
#             kept now ignores a returned error on rebased main.
#             Install the pinned version (must be built with a Go at least as
#             new as go.mod's `go` line, or it refuses to load the config):
#               GOTOOLCHAIN=go1.27.0 GOBIN=$HOME/bin go install \
#                 github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
# test-       `go test -count=1 -run '^$' -exec true ./...` in every affected
# compile     module: compiles AND links every test binary (so test files in
#             reverse-dependencies that call a changed signature are caught)
#             but never executes one (`-exec true` replaces running the
#             binary, so TestMain side effects cannot happen). Measured on
#             this repo's root module (4 cores, 2026-10-04): ~58s cold
#             cache, ~25s warm; changed-packages-only is a few seconds. The
#             repo-wide form is the default because #2641's class is
#             precisely breakage OUTSIDE the PR's own packages; --quick
#             trades that for speed.
# pg          only with KEYORIX_TEST_PG_DSN: `go test -count=1 -timeout 600s
#             <changed pkgs>` with that DSN in the environment (whole changed
#             packages, not just changed tests: #2559's failing assertion
#             lived in an unchanged test whose subject the PR changed).
#
# --- Safety: this never moves your checkout or any branch -----------------
#
# Every PR is checked in its own throwaway worktree under `mktemp -d`,
# created with `git worktree add --detach` (no branch), rebased/merged on a
# DETACHED HEAD, and removed by exact path (`git worktree remove --force`) on
# exit, error, Ctrl-C (INT), TERM or HUP. The only refs this writes are the
# remote-tracking ref refs/remotes/<remote>/main (the initial fetch) and each
# temporary worktree's own FETCH_HEAD/HEAD (per-worktree pseudo-refs). It
# never runs `git worktree prune` (that can deregister worktrees that merely
# aren't visible from a container's view -- see scripts/git-write-guard.sh).
# Rebase/merge run with hooks disabled, signing off and a throwaway identity.
#
# CLAUDE.md's write guard (scripts/git-write-guard.sh, a Claude Code
# PreToolUse hook) inspects the TEXT of a Bash tool call for `git
# rebase`/`git worktree add`/etc. and can deny it. It never sees the git calls
# made inside this script (a hook sees `scripts/ci/precheck-open-prs.sh`, not
# its children), so it neither blocks nor protects them -- the detached-HEAD/
# throwaway-worktree discipline above is what keeps this script from moving
# anyone's HEAD. Running it while another session holds the write lock is
# therefore safe, but if you'd rather not touch the shared .git's worktree
# list at all, run it from a separate `git clone`.
set -uo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
QUICK=0
MODE=run
for arg in "$@"; do
    case "$arg" in
        --quick) QUICK=1 ;;
        --self-test) MODE=selftest ;;
        -h|--help) sed -n '2,/^set -uo/p' "$SELF" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg (try --help)" >&2; exit 64 ;;
    esac
done

REMOTE="${PRECHECK_REMOTE:-origin}"
TRUE_BIN="$(command -v true)"
export GOWORK=off
export GIT_TERMINAL_PROMPT=0

# ---------------------------------------------------------------------------
# Self-test: a throwaway origin (bare) with refs/pull/<N>/head refs, cloned,
# then this very script is run against it. Each case asserts the exact
# verdict row, so a check that silently passes everything fails here.
# ---------------------------------------------------------------------------
if [ "$MODE" = selftest ]; then
    set -e
    ST="$(mktemp -d)"
    trap 'rm -rf "$ST"' EXIT
    G=(git -c user.name=t -c user.email=t@example.invalid -c commit.gpgsign=false -c core.hooksPath=/dev/null)
    mkdir -p "$ST/seed/lib" "$ST/seed/app"
    cd "$ST/seed"
    git init -q -b main
    printf 'module example.com/st\n\ngo 1.22\n' > go.mod
    printf 'version: "2"\nlinters:\n  default: none\n  enable:\n    - errcheck\n' > .golangci.yml
    mkdir -p .github/workflows
    # The pinned lint version is read from here, as in the real repo.
    want_lint="$(sed -n 's/^ *GOLANGCI_LINT_VERSION: *//p' "$(git -C "$(dirname "$SELF")" rev-parse --show-toplevel)/.github/workflows/ci.yml" | head -1)"
    printf 'env:\n  GOLANGCI_LINT_VERSION: %s\n' "$want_lint" > .github/workflows/ci.yml
    cat > lib/lib.go <<'EOF'
package lib

// Do does nothing and cannot fail.
func Do() {}

// Name is the line rebase conflicts are made on.
func Name() string { return "base" }
EOF
    cat > app/app.go <<'EOF'
package app

import "example.com/st/lib"

// Run calls lib.
func Run() { lib.Do() }
EOF
    "${G[@]}" add -A && "${G[@]}" commit -qm base
    base="$(git rev-parse HEAD)"
    mkpr() { # mkpr <N> <message>; commits the current working tree as PR N's head, off base
        "${G[@]}" add -A && "${G[@]}" commit -qm "$2"
        git update-ref "refs/pull/$1/head" HEAD
        git checkout -q --detach "$base"
    }
    git checkout -q --detach "$base"
    # PR 1: clean, adds a package.
    mkdir -p extra && printf 'package extra\n\n// X is fine.\nfunc X() int { return 1 }\n' > extra/x.go
    mkpr 1 "clean"
    # PR 2: breaks the build (undefined identifier).
    printf 'package app\n\n// Bad does not compile.\nfunc Bad() { undefinedThing() }\n' > app/bad.go
    mkpr 2 "build break"
    # PR 3: the #2641 shape -- PR adds a call that is fine against its own
    # base (lib.Do returns nothing) but main later changes Do to return an
    # error, so after rebase the call is an unchecked error (errcheck), while
    # everything still compiles.
    mkdir -p extra && printf 'package extra\n\nimport "example.com/st/lib"\n\n// Y calls Do and ignores nothing (on its own base).\nfunc Y() { lib.Do() }\n' > extra/y.go
    mkpr 3 "calls lib.Do"
    # PR 4: conflicts with main on lib.Name.
    sed -i 's/return "base"/return "pr4"/' lib/lib.go
    mkpr 4 "conflicting edit"
    # main moves on: Do now returns an error (callers on main updated), and
    # Name changes on the same line PR 4 edits.
    git checkout -q main
    cat > lib/lib.go <<'EOF'
package lib

// Do can fail now.
func Do() error { return nil }

// Name is the line rebase conflicts are made on.
func Name() string { return "main" }
EOF
    cat > app/app.go <<'EOF'
package app

import "example.com/st/lib"

// Run calls lib.
func Run() error { return lib.Do() }
EOF
    "${G[@]}" add -A && "${G[@]}" commit -qm "main: Do returns error"
    # PR 5: same line as main, but the branch already merged main and
    # resolved it. Replaying its first commit conflicts; the 3-way merge
    # (= the squash the queue makes) is clean -> rebase column `merge`.
    git checkout -q --detach "$base"
    sed -i 's/return "base"/return "pr5"/' lib/lib.go
    "${G[@]}" add -A && "${G[@]}" commit -qm "pr5 edit"
    "${G[@]}" merge -q main >/dev/null 2>&1 || true
    "${G[@]}" checkout -q main -- lib/lib.go app/app.go
    sed -i 's/return "main"/return "pr5"/' lib/lib.go
    "${G[@]}" add -A && "${G[@]}" commit -qm "merge main into pr5"
    git update-ref refs/pull/5/head HEAD
    git checkout -q main
    git clone -q --bare "$ST/seed" "$ST/origin.git"
    git -C "$ST/seed" for-each-ref --format='%(refname)' 'refs/pull/' | while read -r r; do
        git -C "$ST/origin.git" fetch -q "$ST/seed" "+$r:$r"
    done
    git clone -q "$ST/origin.git" "$ST/clone"

    head_before="$(git -C "$ST/clone" rev-parse HEAD)"
    branch_before="$(git -C "$ST/clone" symbolic-ref HEAD)"
    pass=0; fail=0
    check() { # check <desc> <0 = condition held, else failed>
        if [ "$2" -eq 0 ]; then echo "PASS: $1"; pass=$((pass + 1)); else echo "FAIL: $1"; fail=$((fail + 1)); fi
    }
    row() { awk -v n="$1" '$1 == n' "$ST/out"; }
    col() { row "$1" | awk -v c="$2" '{print $c}'; }

    set +e
    (cd "$ST/clone" && printf '# comment\n\n1\n2   # trailing comment\n3\n4\n5\n' \
        | PRECHECK_LOG_DIR="$ST/logs" "$SELF" --quick) > "$ST/out" 2>&1
    rc=$?
    set -e
    cat "$ST/out"
    echo "---- self-test assertions (rc=$rc) ----"
    check "PR 1 (clean) is OK"                 "$(if [ "$(col 1 8)" = OK ] || [ "$(col 1 8)" = INCOMPLETE ]; then echo 0; else echo 1; fi)"
    check "PR 1 build/vet/test-compile ok"     "$(if [ "$(col 1 3)/$(col 1 4)/$(col 1 6)" = ok/ok/ok ]; then echo 0; else echo 1; fi)"
    check "PR 2 (build break) -> build FAIL"   "$(if [ "$(col 2 3)" = FAIL ] && [ "$(col 2 8)" = FAIL ]; then echo 0; else echo 1; fi)"
    check "PR 4 (conflict) -> CONFLICT"        "$(if [ "$(col 4 2)" = CONFLICT ] && [ "$(col 4 8)" = CONFLICT ]; then echo 0; else echo 1; fi)"
    check "PR 5 (replay conflict, clean 3-way merge) -> rebase=merge, not FAIL/CONFLICT" \
        "$(if [ "$(col 5 2)" = merge ] && [ "$(col 5 3)" = ok ] && [ "$(col 5 8)" != FAIL ] && [ "$(col 5 8)" != CONFLICT ]; then echo 0; else echo 1; fi)"
    check "PR 3 builds after rebase (errcheck is lint-only)" "$(if [ "$(col 3 3)" = ok ]; then echo 0; else echo 1; fi)"
    check "pg column says not-run without a DSN" "$(if [ "$(col 1 7)" = not-run ]; then echo 0; else echo 1; fi)"
    check "non-zero exit when any PR is not OK" "$(if [ "$rc" -ne 0 ]; then echo 0; else echo 1; fi)"
    lint1="$(col 1 5)"
    if [ "$lint1" = ok ]; then
        check "PR 1 lint ok"                       "$(if [ "$(col 1 8)" = OK ]; then echo 0; else echo 1; fi)"
        check "PR 3 (#2641 shape) -> lint FAIL"    "$(if [ "$(col 3 5)" = FAIL ] && [ "$(col 3 8)" = FAIL ]; then echo 0; else echo 1; fi)"
    else
        echo "NOTE: lint is '$lint1' here (no golangci-lint $want_lint) -- errcheck red/green not exercised;"
        echo "      set GOLANGCI_LINT to a $want_lint binary to run it."
        check "skipped lint is not printed as ok"   "$(if [[ "$lint1" == SKIP* ]]; then echo 0; else echo 1; fi)"
        check "skipped lint makes overall INCOMPLETE, not OK" "$(if [ "$(col 1 8)" = INCOMPLETE ]; then echo 0; else echo 1; fi)"
    fi
    check "caller's HEAD did not move"     "$(if [ "$(git -C "$ST/clone" rev-parse HEAD)" = "$head_before" ]; then echo 0; else echo 1; fi)"
    check "caller's branch did not change" "$(if [ "$(git -C "$ST/clone" symbolic-ref HEAD)" = "$branch_before" ]; then echo 0; else echo 1; fi)"
    check "no branch created"              "$(if [ "$(git -C "$ST/clone" for-each-ref refs/heads | wc -l)" -eq 1 ]; then echo 0; else echo 1; fi)"
    check "no temp worktree left behind"   "$(if [ "$(git -C "$ST/clone" worktree list | wc -l)" -eq 1 ]; then echo 0; else echo 1; fi)"

    # All-clean run exits 0 (the green direction of the exit status).
    set +e
    (cd "$ST/clone" && echo 1 | PRECHECK_LOG_DIR="$ST/logs2" "$SELF" --quick) > "$ST/out2" 2>&1
    rc2=$?
    set -e
    if [ "$lint1" = ok ]; then
        check "all-OK input exits 0" "$(if [ "$rc2" -eq 0 ]; then echo 0; else echo 1; fi)"
    else
        check "all-OK-but-lint-skipped input exits 2 (INCOMPLETE)" "$(if [ "$rc2" -eq 2 ]; then echo 0; else echo 1; fi)"
    fi

    # Ctrl-C cleanup: deliver SIGINT to a run while its temp worktree exists
    # (PRECHECK_SELFTEST_HOLD pauses right after `worktree add`), then
    # confirm the worktree is gone and the exit status is 130. `timeout -s
    # INT` runs the script in the foreground (a backgrounded non-interactive
    # child would start with SIGINT ignored, which proves nothing).
    set +e
    (cd "$ST/clone" && echo 1 | PRECHECK_SELFTEST_HOLD=3 PRECHECK_LOG_DIR="$ST/logs3" \
        timeout --preserve-status -s INT 1 "$SELF" > "$ST/out3" 2>&1)
    rc3=$?
    set -e
    check "Ctrl-C mid-run: interrupted (rc=$rc3), said so, no worktree left" \
        "$(if [ "$rc3" -eq 130 ] && grep -q 'interrupted -- cleaning up' "$ST/out3" \
            && [ "$(git -C "$ST/clone" worktree list | wc -l)" -eq 1 ] \
            && [ -z "$(ls -A "$ST/clone/.git/worktrees" 2>/dev/null)" ]; then echo 0; else echo 1; fi)"

    echo "self-test: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
    exit $?
fi

# ---------------------------------------------------------------------------
# Main run
# ---------------------------------------------------------------------------
REPO="$(git rev-parse --show-toplevel 2>/dev/null)" || { echo "not inside a git checkout" >&2; exit 64; }
TMP="$(mktemp -d)"
LOGS="${PRECHECK_LOG_DIR:-$(mktemp -d -t precheck-logs.XXXXXX)}"
mkdir -p "$LOGS"
WORKTREES=()

# shellcheck disable=SC2329 # invoked via `trap cleanup EXIT`
cleanup() {
    local wt
    for wt in "${WORKTREES[@]}"; do
        git -C "$REPO" worktree remove --force "$wt" >/dev/null 2>&1 || true
    done
    rm -rf "$TMP"
}
trap cleanup EXIT
trap 'echo "interrupted -- cleaning up temporary worktrees" >&2; exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# Read PR numbers.
PRS=()
while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [ -z "$line" ] && continue
    case "$line" in
        *[!0-9]*) echo "ignoring non-numeric line: $line" >&2; continue ;;
    esac
    PRS+=("$line")
done
[ "${#PRS[@]}" -eq 0 ] && { echo "no PR numbers on stdin" >&2; exit 64; }

echo "fetching $REMOTE main ..." >&2
if ! git -C "$REPO" fetch -q "$REMOTE" main; then
    echo "cannot fetch $REMOTE main" >&2; exit 1
fi
MAIN_SHA="$(git -C "$REPO" rev-parse "refs/remotes/$REMOTE/main")"
echo "main = $MAIN_SHA" >&2

# Lint binary + the version CI pins (read, not hard-coded).
WANT_LINT="$(git -C "$REPO" show "$MAIN_SHA:.github/workflows/ci.yml" 2>/dev/null \
    | sed -n 's/^ *GOLANGCI_LINT_VERSION: *//p' | head -1 | tr -d '"'"'"' ')"
LINT_BIN="${GOLANGCI_LINT:-$(command -v golangci-lint || true)}"
LINT_SKIP=""
if [ -z "$LINT_BIN" ] || [ ! -x "$LINT_BIN" ]; then
    LINT_SKIP="SKIP(lint-missing)"
else
    have="$("$LINT_BIN" --version 2>/dev/null | sed -n 's/.*has version \([^ ]*\).*/\1/p')"
    if [ -n "$WANT_LINT" ] && [ "v${have#v}" != "v${WANT_LINT#v}" ]; then
        LINT_SKIP="SKIP(lint-version)"
        echo "golangci-lint at $LINT_BIN is ${have:-unknown}; CI pins $WANT_LINT -- lint will be skipped. Set GOLANGCI_LINT to a $WANT_LINT binary." >&2
    fi
fi

GIT_W=(git -c user.name=precheck -c user.email=precheck@localhost.invalid
       -c commit.gpgsign=false -c core.hooksPath=/dev/null -c rerere.enabled=false)

# step <logname> <dir> <cmd...> -> sets STATUS to ok/FAIL; tool errors are
# classified by the caller where the tool distinguishes them.
RC=0
step() {
    local log="$1" dir="$2"; shift 2
    (cd "$dir" && "$@") > "$log" 2>&1
    RC=$?
    if [ "$RC" -eq 0 ]; then STATUS=ok; else STATUS=FAIL; fi
}

# fail_excerpt <go-test-log>: each `--- FAIL` block (the line plus its
# indented continuation), `panic:` lines and per-package FAIL lines -- not
# the surrounding test chatter, which in this repo is thousands of lines.
fail_excerpt() {
    awk '/^[[:space:]]*--- FAIL/ {inb=1; print; next}
         inb && /^[[:space:]]/ {print; next}
         {inb=0}
         /^panic:/ || /^FAIL[[:space:]]/ {print}' "$1" | head -40
}

# worst <current> <new>: worst-of, ok < n/a-ish < SKIP < ERROR < FAIL.
rank() { case "$1" in FAIL) echo 4 ;; ERROR) echo 3 ;; SKIP*) echo 2 ;; ok) echo 1 ;; *) echo 0 ;; esac; }
worst() { if [ "$(rank "$2")" -gt "$(rank "$1")" ]; then echo "$2"; else echo "$1"; fi; }

ROWS=()
DETAILS=()
any_fail=0
any_incomplete=0

for n in "${PRS[@]}"; do
    wt="$TMP/pr-$n"
    plog="$LOGS/pr-$n"
    mkdir -p "$plog"
    r_rebase="-"; r_build="-"; r_vet="-"; r_lint="-"; r_tc="-"; r_pg="-"; overall=""
    echo "== PR #$n" >&2

    if ! git -C "$REPO" worktree add -q --detach "$wt" "$MAIN_SHA" > "$plog/worktree.log" 2>&1; then
        ROWS+=("$n ERROR - - - - - ERROR"); DETAILS+=("PR #$n: worktree add failed: $(head -3 "$plog/worktree.log")"); any_fail=1; continue
    fi
    WORKTREES+=("$wt")
    # Self-test only: hold here so the Ctrl-C case can interrupt while a
    # temporary worktree provably exists.
    [ -n "${PRECHECK_SELFTEST_HOLD:-}" ] && sleep "$PRECHECK_SELFTEST_HOLD"

    if ! git -C "$wt" fetch -q "$REMOTE" "refs/pull/$n/head" > "$plog/fetch.log" 2>&1; then
        ROWS+=("$n ERROR - - - - - ERROR"); DETAILS+=("PR #$n: cannot fetch refs/pull/$n/head: $(head -3 "$plog/fetch.log")"); any_fail=1
        git -C "$REPO" worktree remove --force "$wt" >/dev/null 2>&1; continue
    fi
    pr_sha="$(git -C "$wt" rev-parse FETCH_HEAD)"
    git -C "$wt" checkout -q --detach "$pr_sha"
    if "${GIT_W[@]}" -C "$wt" rebase -q "$MAIN_SHA" > "$plog/rebase.log" 2>&1; then
        r_rebase=ok
    else
        "${GIT_W[@]}" -C "$wt" rebase --abort >/dev/null 2>&1
        git -C "$wt" checkout -q --detach "$MAIN_SHA"
        if "${GIT_W[@]}" -C "$wt" merge -q --no-edit "$pr_sha" > "$plog/merge.log" 2>&1; then
            r_rebase=merge
        else
            "${GIT_W[@]}" -C "$wt" merge --abort >/dev/null 2>&1
            files="$(grep -h -o 'CONFLICT ([^)]*): .* in [^ ]*' "$plog/rebase.log" "$plog/merge.log" 2>/dev/null | sed 's/.* in //' | sort -u | tr '\n' ' ')"
            ROWS+=("$n CONFLICT - - - - - CONFLICT"); DETAILS+=("PR #$n: conflicts with main ${MAIN_SHA:0:10}: ${files:-see $plog/rebase.log}")
            any_fail=1
            git -C "$REPO" worktree remove --force "$wt" >/dev/null 2>&1; continue
        fi
    fi

    # --- modules and changed packages -----------------------------------
    mapfile -t MODS < <(cd "$wt" && find . \( -name vendor -o -name node_modules -o -name testdata -o -name .git \) -prune -o -name go.mod -print \
        | sed 's|^\./||; s|/\{0,1\}go\.mod$||' | sed 's|^$|.|' | sort)
    mod_of() { # longest module dir containing path $1
        local p="$1" best="." m
        for m in "${MODS[@]}"; do
            [ "$m" = "." ] && continue
            case "$p" in "$m"/*) [ "${#m}" -gt "${#best}" ] || [ "$best" = "." ] && best="$m" ;; esac
        done
        echo "$best"
    }
    declare -A PKGS=() AFFECTED=()
    while IFS= read -r f; do
        [ -z "$f" ] && continue
        m="$(mod_of "$f")"
        case "$f" in
            */testdata/*|testdata/*|*/vendor/*|vendor/*) continue ;;
            go.mod|go.sum|*/go.mod|*/go.sum) AFFECTED[$m]=1; PKGS[$m]="./..."; continue ;;
            *.go) ;;
            *) continue ;;
        esac
        AFFECTED[$m]=1
        d="$(dirname "$f")"
        compgen -G "$wt/$d/*.go" > /dev/null || continue
        [ "${PKGS[$m]:-}" = "./..." ] && continue
        if [ "$m" = "." ]; then rel="./$d"; else rel="./${d#"$m"/}"; [ "$d" = "$m" ] && rel="."; fi
        [ "$d" = "." ] && rel="."
        case " ${PKGS[$m]:-} " in *" $rel "*) ;; *) PKGS[$m]="${PKGS[$m]:-} $rel" ;; esac
    done < <(git -C "$wt" diff --name-only "$MAIN_SHA" HEAD)

    # Transitive closure over local `replace` directives.
    changed=1
    while [ "$changed" -eq 1 ]; do
        changed=0
        for m in "${MODS[@]}"; do
            [ -n "${AFFECTED[$m]:-}" ] && continue
            while IFS= read -r tgt; do
                [ -z "$tgt" ] && continue
                tdir="$(cd "$wt/$m" 2>/dev/null && cd "$tgt" 2>/dev/null && pwd -P)" || continue
                trel="$(realpath --relative-to="$(cd "$wt" && pwd -P)" "$tdir")"
                if [ -n "${AFFECTED[$trel]:-}" ]; then AFFECTED[$m]=1; changed=1; break; fi
            done < <(cd "$wt/$m" && go mod edit -json 2>/dev/null | jq -r '.Replace[]?.New.Path | select(startswith("./") or startswith("../"))')
        done
    done

    if [ "${#AFFECTED[@]}" -eq 0 ]; then
        r_build=n/a; r_vet=n/a; r_lint=n/a; r_tc=n/a
        if [ -n "${KEYORIX_TEST_PG_DSN:-}" ]; then r_pg=n/a; else r_pg=not-run; fi
    else
        r_build=n/a; r_vet=n/a; r_tc=n/a; r_lint=n/a; r_pg=n/a
        for m in $(printf '%s\n' "${!AFFECTED[@]}" | sort); do
            tag="$(echo "$m" | tr '/.' '__')"
            mdir="$wt/$m"
            read -r -a pk <<< "${PKGS[$m]:-}"

            step "$plog/build-$tag.log" "$mdir" go build ./...
            r_build="$(worst "$r_build" "$STATUS")"
            [ "$STATUS" = FAIL ] && DETAILS+=("PR #$n build ($m):"$'\n'"$(head -20 "$plog/build-$tag.log")")

            if [ "${#pk[@]}" -gt 0 ]; then
                step "$plog/vet-$tag.log" "$mdir" go vet "${pk[@]}"
                r_vet="$(worst "$r_vet" "$STATUS")"
                [ "$STATUS" = FAIL ] && DETAILS+=("PR #$n vet ($m):"$'\n'"$(head -20 "$plog/vet-$tag.log")")

                if [ -n "$LINT_SKIP" ]; then
                    r_lint="$(worst "$r_lint" "$LINT_SKIP")"
                else
                    step "$plog/lint-$tag.log" "$mdir" "$LINT_BIN" run "${pk[@]}"
                    # golangci-lint: 0 clean, 1 issues found, anything else = it
                    # could not run (bad config, typecheck load failure, timeout).
                    if [ "$RC" -gt 1 ]; then STATUS=ERROR; fi
                    r_lint="$(worst "$r_lint" "$STATUS")"
                    [ "$STATUS" != ok ] && DETAILS+=("PR #$n lint ($m, rc=$RC):"$'\n'"$(head -30 "$plog/lint-$tag.log")")
                fi
            fi

            if [ "$QUICK" -eq 1 ]; then tcp=("${pk[@]}"); else tcp=(./...); fi
            if [ "${#tcp[@]}" -gt 0 ]; then
                step "$plog/testcompile-$tag.log" "$mdir" go test -count=1 -run '^$' -exec "$TRUE_BIN" "${tcp[@]}"
                r_tc="$(worst "$r_tc" "$STATUS")"
                [ "$STATUS" = FAIL ] && DETAILS+=("PR #$n test-compile ($m):"$'\n'"$(grep -v -e '^ok ' -e 'no test files' "$plog/testcompile-$tag.log" | head -20)")
            fi

            if [ -n "${KEYORIX_TEST_PG_DSN:-}" ] && [ "${#pk[@]}" -gt 0 ]; then
                step "$plog/pg-$tag.log" "$mdir" env KEYORIX_TEST_PG_DSN="$KEYORIX_TEST_PG_DSN" go test -count=1 -timeout 600s "${pk[@]}"
                r_pg="$(worst "$r_pg" "$STATUS")"
                [ "$STATUS" = FAIL ] && DETAILS+=("PR #$n pg ($m):"$'\n'"$(fail_excerpt "$plog/pg-$tag.log")")
            fi
        done
        [ -z "${KEYORIX_TEST_PG_DSN:-}" ] && r_pg=not-run
    fi
    unset PKGS AFFECTED

    overall=OK
    for v in "$r_build" "$r_vet" "$r_lint" "$r_tc" "$r_pg"; do
        case "$v" in
            FAIL|ERROR) overall=FAIL ;;
            SKIP*) [ "$overall" = OK ] && overall=INCOMPLETE ;;
        esac
    done
    [ "$overall" = FAIL ] && any_fail=1
    [ "$overall" = INCOMPLETE ] && any_incomplete=1
    ROWS+=("$n $r_rebase $r_build $r_vet $r_lint $r_tc $r_pg $overall")

    git -C "$REPO" worktree remove --force "$wt" >/dev/null 2>&1
done

echo
echo "main: $MAIN_SHA   lint: ${LINT_SKIP:-golangci-lint $WANT_LINT}   test-compile: $([ "$QUICK" -eq 1 ] && echo changed-pkgs || echo affected-modules)"
# Fixed-width table (no `column`: not installed everywhere).
for r in "PR rebase build vet lint test-compile pg overall" "${ROWS[@]}"; do
    # shellcheck disable=SC2086 # word-splitting the row into its columns is the point
    printf '%-6s %-9s %-6s %-6s %-19s %-13s %-8s %s\n' $r
done
if [ "${#DETAILS[@]}" -gt 0 ]; then
    echo
    echo "---- details ----"
    printf '%s\n\n' "${DETAILS[@]}"
fi
echo "logs: $LOGS"

if [ "$any_fail" -eq 1 ]; then exit 1; fi
if [ "$any_incomplete" -eq 1 ]; then exit 2; fi
exit 0
