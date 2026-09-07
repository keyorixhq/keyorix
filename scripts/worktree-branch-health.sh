#!/bin/bash
# worktree-branch-health.sh — report-only. Detection, not automation: this
# script never deletes, pushes, or modifies anything. It exists because a
# 2026-09-07 incident found something removed ~67 git-worktree registrations
# unprompted, and separately that a branch (postgres-ha-locking-contention-
# verification) whose 4 commits were ALL already merged under different SHAs
# nearly caused a 12-file conflict-resolution pass recreating already-landed
# security code during a routine rebase. Two distinct failure directions —
# real uncommitted/unpushed work going unnoticed, and stale fully-duplicate
# branches being mistaken for live work — and this checks for both.
#
# Run on demand for the full report (both sections). The SessionStart hook
# runs it with --worktrees-only: section 2's full-repo branch sweep is
# expensive to inject into every session's context (100+ lines in this repo)
# and isn't session-start-scoped in the request that added this script —
# only the worktree check was asked for at session start.
# Exits 0 always (report-only); a human decides what (if anything) to do next.
set -uo pipefail

WORKTREES_ONLY=0
if [ "${1:-}" = "--worktrees-only" ]; then
    WORKTREES_ONLY=1
fi

DEFAULT_BRANCH="${DEFAULT_BRANCH:-origin/main}"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"
if [ -z "$REPO_ROOT" ]; then
    echo "Not inside a git repository." >&2
    exit 0
fi
cd "$REPO_ROOT" || exit 0

echo "== worktree-branch-health: $(git remote get-url origin 2>/dev/null || echo "$REPO_ROOT") =="
echo

# --- Section 1: every registered worktree — uncommitted or unpushed work ---
echo "-- Worktrees with uncommitted or unpushed work --"
found_worktree_issue=0
git worktree list --porcelain | awk '/^worktree /{print $2}' | while IFS= read -r wt_path; do
    [ -d "$wt_path" ] || { echo "  [unreachable] $wt_path (path missing — foreign/remote-session worktree?)"; continue; }
    branch="$(git -C "$wt_path" symbolic-ref --short -q HEAD || echo "(detached)")"

    dirty=""
    if [ -n "$(git -C "$wt_path" status --porcelain 2>/dev/null)" ]; then
        dirty="uncommitted changes"
    fi

    unpushed=""
    if [ "$branch" != "(detached)" ]; then
        upstream="$(git -C "$wt_path" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null || true)"
        if [ -n "$upstream" ]; then
            ahead="$(git -C "$wt_path" rev-list --count "${upstream}..HEAD" 2>/dev/null || echo 0)"
            [ "$ahead" -gt 0 ] && unpushed="${ahead} commit(s) ahead of ${upstream}"
        else
            ahead="$(git -C "$wt_path" rev-list --count "${DEFAULT_BRANCH}..HEAD" 2>/dev/null || echo 0)"
            [ "$ahead" -gt 0 ] && unpushed="${ahead} commit(s) ahead of ${DEFAULT_BRANCH}, no upstream branch (never pushed)"
        fi
    fi

    if [ -n "$dirty" ] || [ -n "$unpushed" ]; then
        echo "  [ATTENTION] $wt_path (branch: $branch)"
        [ -n "$dirty" ] && echo "      - $dirty"
        [ -n "$unpushed" ] && echo "      - $unpushed"
    fi
done
echo "  (worktrees with nothing to report are omitted)"
echo

if [ "$WORKTREES_ONLY" -eq 1 ]; then
    echo "(run without --worktrees-only for the full local-branch stranded/duplicate sweep)"
    echo "== end of report — nothing above was modified =="
    exit 0
fi

# --- Section 2: local branches whose commits are NOT reachable from default ---
# Two-tier: cheap ancestry check first (branch --no-merged), then git cherry
# only on that subset to split "genuinely ahead" from "patch-identical
# duplicate already merged under a different SHA" (squash-merge blind spot —
# --is-ancestor / plain ahead-count both lie here, per CLAUDE.md's own
# documented squash-merge caveat).
echo "-- Local branches not fully merged into ${DEFAULT_BRANCH} --"
stranded_count=0
duplicate_count=0
git branch --no-merged "$DEFAULT_BRANCH" --format='%(refname:short)' | while IFS= read -r branch; do
    [ -z "$branch" ] && continue
    cherry_out="$(git cherry "$DEFAULT_BRANCH" "$branch" 2>/dev/null)"
    [ -z "$cherry_out" ] && continue

    genuinely_new="$(echo "$cherry_out" | grep -c '^+' || true)"
    duplicate="$(echo "$cherry_out" | grep -c '^-' || true)"

    if [ "$genuinely_new" -gt 0 ]; then
        echo "  [STRANDED] $branch — ${genuinely_new} commit(s) not equivalent to anything on ${DEFAULT_BRANCH}"
    elif [ "$duplicate" -gt 0 ]; then
        echo "  [DUPLICATE] $branch — all ${duplicate} commit(s) are patch-equivalent to something already on ${DEFAULT_BRANCH} (likely squash-merged under a different SHA; safe-to-delete candidate, verify with 'git diff ${branch} ${DEFAULT_BRANCH}' before removing)"
    fi
done
echo "  (branches already an ancestor of ${DEFAULT_BRANCH} — the ordinary merged case — are omitted; this only lists the two lying-ahead-count shapes)"
echo

echo "== end of report — nothing above was modified =="
