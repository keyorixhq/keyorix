#!/bin/bash
# git-write-guard.sh -- one-writer-per-repo enforcement (CLAUDE.md operating
# model, added 2026-09-07 after a week of concurrent sessions silently moving
# HEAD in a shared main checkout, racing each other's commits, and one
# session's autonomous daemon committing over another's in-progress ADR draft).
#
# The lock lives at $(git rev-parse --git-common-dir)/write-lock.json -- that
# path is IDENTICAL for a main checkout and every one of its linked worktrees
# (they share one .git), and DIFFERENT for an independent `git clone` of the
# same repo. That's deliberate: this repo's operating model is one writer per
# .git (main checkout + all its worktrees combined), not one writer per
# directory -- a separate clone is a different .git and is exempt by design.
#
# No persistent PID is available to check liveness (hooks are short-lived
# subprocesses; the Claude Code session that invokes them isn't). This uses
# timestamp-based staleness instead. The refresh only happens on a GATED git
# subcommand (see below) -- NOT on a timer, and NOT on ordinary Edit/Write/
# Bash-non-git activity. Confirmed 2026-09-07: agents here routinely run
# 40-80 minutes and can go long stretches without touching a gated git
# subcommand at all (e.g. one commit at the start of a session, then 60+
# minutes of pure editing/testing before the next one) -- during that gap
# the lock is NOT being refreshed, so a 20-minute window would silently
# expire mid-work and let a second session claim it, arriving without any
# warning to either party until the first session's next gated git call
# gets denied (loud, but only after the collision already happened at the
# file-editing level). STALE_SECONDS is set well past the longest observed
# single-session runtime for this reason -- widening the window, not adding
# a timer-based refresh (a hook can't run on a timer; it only runs when
# something invokes it), is the actual fix for that gap. A crashed/abandoned
# session's lock still self-clears, just on a multi-hour horizon instead of
# a 20-minute one -- an accepted tradeoff given the alternative is a silent
# collision, not a merely slower one.
set -uo pipefail

MODE="${1:?usage: git-write-guard.sh session-start|gate}"
STALE_SECONDS=10800

payload="$(cat)"
sid="$(echo "$payload" | jq -r '.session_id // empty')"
[ -z "$sid" ] && exit 0

# Parse the actual command being gated (gate mode only -- session-start has
# no tool_input.command, and runs in the harness's own ambient cwd, which is
# already correct). Extract both the git subcommand AND any `-C <path>`
# target: the subcommand determines WHETHER this call is guarded at all; the
# -C target determines WHERE the guard's own git rev-parse calls must run --
# using plain ambient cwd here would silently mis-check any command of the
# form `git -C <worktree> ...`, which is this repo's own dominant idiom for
# operating on a worktree from a shell whose cwd is the main checkout (the -C
# flag changes what path GIT operates on; it does not change the shell's own
# cwd, so a naive `git rev-parse` inside this hook -- unaware of the -C in
# the command it's gating -- would resolve against the wrong tree entirely).
GIT_C=""
subcmd=""
skip_worktree_check=0
if [ "$MODE" = "gate" ]; then
    cmd_str="$(echo "$payload" | jq -r '.tool_input.command // empty')"
    set -- $cmd_str
    found_git=0
    while [ "$#" -gt 0 ]; do
        tok="$1"; shift
        if [ "$found_git" -eq 0 ]; then
            [ "$tok" = "git" ] && found_git=1
            continue
        fi
        case "$tok" in
            -C) GIT_C="$1"; shift ;;
            -c|--git-dir|--work-tree) shift ;;
            -*) ;;
            *) subcmd="$tok"; break ;;
        esac
    done
fi

# Hoisted above the subcommand case below: check 3 (worktree prune) needs it
# during classification, before the write-lock section that used to be its
# only caller.
#
# --path-format=absolute is deliberate, not decoration: plain
# `rev-parse --git-common-dir` returns a path relative to THIS PROCESS'S OWN
# cwd, not to the -C target -- confirmed empirically (git 2.50.1, both a
# `-C <path>` target and a bare invocation from a non-repo cwd return the
# literal string ".git"). That relative string, used unmodified as a
# filesystem path elsewhere in this script (the lock path below, and the
# worktree-prune resolution check), silently resolves against the HOOK
# PROCESS's ambient cwd instead of the repo actually being gated -- the
# exact "-C changes what git operates on, not the shell's own cwd" trap this
# file's own header comment already warns about for git_at, just not (until
# now) applied to its own output. --path-format=absolute forces an absolute
# result regardless of invocation context (git >=2.31, well below this
# repo's floor).
git_at() {
    if [ -n "$GIT_C" ]; then
        git -C "$GIT_C" "$@"
    else
        git "$@"
    fi
}

# deny prints the standard PreToolUse block payload and exits. Every call
# site below MUST exit 0 regardless of allow/deny -- this hook's contract
# communicates the decision entirely through hookSpecificOutput.
# permissionDecision, never through the process exit code (matching every
# other deny path already in this file).
deny() {
    jq -n --arg reason "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
    exit 0
}

if [ "$MODE" = "gate" ]; then
    # Only HEAD/branch-state-mutating subcommands are guarded -- this is the
    # documented incident class ("HEAD moving inside a shared .git"), not
    # "every git invocation." Gating git status/log/diff/show etc. would just
    # break normal read-only work for no safety gain.
    case "$subcmd" in
        reset|checkout)
            # `git reset -- <paths>` / `git checkout -- <paths>` are
            # pathspec-scoped: they touch only the index/working-tree
            # content for those paths and never move HEAD or the current
            # branch pointer -- functionally a bulk unstage/restore, not
            # the HEAD-moving operation this guard exists for. Only the
            # bare/commit-target form (no `--`) is guarded. Checked via a
            # literal `--` in the remaining args, which is the form both
            # subcommands require to disambiguate a pathspec from a
            # revision anyway.
            for a in "$@"; do
                [ "$a" = "--" ] && exit 0
            done
            ;;
        commit|switch|rebase|merge|cherry-pick|revert|pull|am) ;;
        push)
            # Bare --force overwrites work whose existence the pusher never
            # checked -- --force-with-lease at least fails closed when the
            # remote ref moved since the pusher's own last fetch. Tracks
            # LAST-WINS across the arg list (matching git's own option
            # precedence: a later --force-with-lease after an earlier
            # --force makes the push safe again, and vice versa), not mere
            # presence -- a presence-only check would wrongly clear a
            # trailing bare --force just because --force-with-lease also
            # appears earlier on the line. A single-dash cluster containing
            # `f` (e.g. `-fu`, `-nf`) counts as --force: push's other short
            # flags (v,q,n,u,d,o,4,6) don't collide with that letter, so
            # this doesn't false-positive on them.
            force_mode=""
            for a in "$@"; do
                case "$a" in
                    --force-with-lease|--force-with-lease=*|--force-if-includes) force_mode="lease" ;;
                    --force) force_mode="bare" ;;
                    --no-force) force_mode="" ;;
                    -[a-zA-Z]*) case "$a" in *f*) force_mode="bare" ;; esac ;;
                esac
            done
            if [ "$force_mode" = "bare" ]; then
                deny "Bare --force on push overwrites whatever is on the remote right now, sight unseen -- the pusher never checked what's there. Use --force-with-lease instead: it still force-pushes, but fails closed if the remote ref moved since your last fetch, instead of silently discarding it."
            fi
            # push doesn't move local HEAD or the current branch pointer --
            # the downstream "must be in a dedicated worktree" check below
            # exists for a different, unrelated invariant (two sessions'
            # HEAD-moving operations colliding in a shared main checkout)
            # that a remote-ref push was never subject to before this
            # subcommand had any case arm at all. Exempt via the same
            # mechanism worktree add/remove/prune/move already use, once
            # this check itself has passed -- still subject to the write-
            # lock contestation check above this exemption, just not the
            # worktree-specific one below it.
            skip_worktree_check=1
            ;;
        branch)
            # A local branch may be an active working checkout (this repo's
            # own worktree model) carrying uncommitted work -- there is no
            # recovery path for what was never committed. Unconditional:
            # this blocks deleting ANY local branch through this gate, not
            # just the currently-checked-out one, matching CLAUDE.md's
            # standing "never delete a local branch" rule -- judgment about
            # which branches are safe to remove belongs to a human or an
            # explicit instruction, not a heuristic in this hook.
            # -r/--remote(s) is exempted: `git branch -d -r <name>` deletes
            # a REMOTE-TRACKING ref (refs/remotes/...), not a local branch a
            # worktree could have checked out -- a different, lower-risk
            # operation this rule was never about.
            has_delete=0
            has_remote=0
            for a in "$@"; do
                case "$a" in
                    --delete) has_delete=1 ;;
                    --remotes|--remote) has_remote=1 ;;
                    -[a-zA-Z]*)
                        case "$a" in *[dD]*) has_delete=1 ;; esac
                        case "$a" in *r*) has_remote=1 ;; esac
                        ;;
                esac
            done
            if [ "$has_delete" -eq 1 ] && [ "$has_remote" -eq 0 ]; then
                deny "git branch -d/-D/--delete refused: a local branch may be an active working checkout (this repo runs on worktrees) carrying uncommitted work, and there is no recovery path for what was never committed. Leave the branch -- if it's genuinely unneeded, that is a decision for a human, not this gate."
            fi
            # Same reasoning as push above: branch (list/create/delete-of-a-
            # non-HEAD-ref) doesn't move THIS process's own HEAD, so the
            # downstream worktree-specific check is unrelated and was never
            # applied to it before this subcommand had a case arm.
            skip_worktree_check=1
            ;;
        worktree)
            # only add/remove/prune/move mutate the shared registry; list
            # and lock/unlock are read-only-equivalent for this purpose.
            wt_subcmd="${1:-}"
            case "$wt_subcmd" in
                add|remove|prune|move) skip_worktree_check=1 ;;
                *) exit 0 ;;
            esac
            if [ "$wt_subcmd" = "prune" ]; then
                # In a mounted or containerised view, worktrees registered
                # at HOST paths are invisible from this process, and git
                # reports them as prunable -- a prune there deregisters
                # every live worktree at once (this has already happened at
                # scale in this repository). Mechanical test: for each
                # registered worktree's gitdir file, does the recorded
                # path's PARENT directory (the worktree's own root, not the
                # .git file itself) exist from THIS process's view? If any
                # do not, this view cannot see host worktrees and prune
                # must be refused outright -- not just for the specific
                # unresolvable entries, since the same blind spot could
                # just as easily be hiding others that happen to look
                # resolvable by coincidence (e.g. a reused path).
                gc_abs="$(git_at rev-parse --path-format=absolute --git-common-dir 2>/dev/null)"
                unresolvable=""
                if [ -n "$gc_abs" ] && [ -d "$gc_abs/worktrees" ]; then
                    for gd_file in "$gc_abs"/worktrees/*/gitdir; do
                        [ -f "$gd_file" ] || continue
                        recorded="$(cat "$gd_file" 2>/dev/null)"
                        [ -z "$recorded" ] && continue
                        parent="$(dirname "$recorded")"
                        if [ ! -e "$parent" ]; then
                            unresolvable="${unresolvable}${unresolvable:+, }$parent"
                        fi
                    done
                fi
                if [ -n "$unresolvable" ]; then
                    deny "git worktree prune refused: at least one registered worktree's path does not resolve from this process's view ($unresolvable) -- in a mounted or containerised view that means the host's own worktrees are simply invisible here, not actually gone, and prune would deregister them all. Verify gitdir resolution (does every path under \$(git rev-parse --git-common-dir)/worktrees/*/gitdir actually exist from here?) before pruning, or run prune from the view that can actually see those paths."
                fi
            fi
            ;;
        *) exit 0 ;;
    esac
fi

lock="$(git_at rev-parse --path-format=absolute --git-common-dir 2>/dev/null)/write-lock.json"
[ -z "$lock" ] && exit 0

now="$(date -u +%s)"
other_sid=""
other_age=0
if [ -f "$lock" ]; then
    other_sid="$(jq -r '.sessionId // empty' "$lock" 2>/dev/null)"
    other_ts="$(jq -r '.claimedAtEpoch // 0' "$lock" 2>/dev/null)"
    other_age=$(( now - other_ts ))
fi

contested=0
if [ -n "$other_sid" ] && [ "$other_sid" != "$sid" ] && [ "$other_age" -lt "$STALE_SECONDS" ]; then
    contested=1
fi

reason="Another session ($other_sid) claimed write access to this repo ${other_age}s ago (<${STALE_SECONDS}s = active). Per CLAUDE.md's one-writer-per-repo operating model: work read-only here, or use a separate 'git clone' (not a worktree -- worktrees share this .git and this lock)."

if [ "$MODE" = "session-start" ]; then
    if [ "$contested" -eq 1 ]; then
        jq -n --arg ctx "ACTIVE-WRITER-LOCK: $reason" '{hookSpecificOutput:{hookEventName:"SessionStart",additionalContext:$ctx}}'
        exit 0
    fi
    jq -n --arg sid "$sid" --argjson ts "$now" '{sessionId:$sid, claimedAtEpoch:$ts}' > "$lock"
    exit 0
fi

if [ "$MODE" = "gate" ]; then
    if [ "$contested" -eq 1 ]; then
        jq -n --arg reason "$reason" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$reason}}'
        exit 0
    fi

    # Not contested -- this session is (or becomes) the writer. Refresh the
    # lock so it stays warm while this session keeps acting.
    jq -n --arg sid "$sid" --argjson ts "$now" '{sessionId:$sid, claimedAtEpoch:$ts}' > "$lock"

    # worktree add/remove/prune/move, push, and branch are all exempt from
    # the "must already be in a worktree" check below -- none of them move
    # THIS process's own HEAD, which is the specific incident class that
    # check exists for. worktree add/remove/prune/move are inherently main-
    # checkout-administrative (worktree add FROM the main checkout is how
    # you GET a worktree in the first place; requiring one first is a
    # bootstrapping deadlock, not a safety property). push writes a remote
    # ref; branch list/create/delete touches a ref, not HEAD. The lock check
    # above still applies to all of them -- this exemption only narrows
    # which DOWNSTREAM check applies, not whether the write-lock does.
    if [ "$skip_worktree_check" -eq 1 ]; then
        exit 0
    fi

    # A live single writer working directly in the main checkout,
    # unworktreed, is still the other half of this week's incident -- HEAD
    # moving under a concurrent read/inspection from anyone else, even a
    # well-behaved second session that's only ever reading.
    gd="$(git_at rev-parse --absolute-git-dir 2>/dev/null)"
    gc="$(cd "$(git_at rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" 2>/dev/null && pwd -P)"
    gd_r="$(cd "$gd" 2>/dev/null && pwd -P)"
    if [ -n "$gd_r" ] && [ "$gd_r" = "$gc" ]; then
        jq -n '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:"Commits/checkouts/rebases must happen in a dedicated worktree, not the shared main checkout -- run EnterWorktree (or git worktree add) first. See CLAUDE.md: start in a worktree, commit+push as your last act."}}'
    fi
    exit 0
fi
