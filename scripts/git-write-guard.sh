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
# timestamp-based staleness instead: a lock claimed/refreshed within the last
# 20 minutes counts as active. An honest limitation, not a bug -- a crashed
# session's lock self-clears in <=20 minutes rather than wedging the repo
# forever, and an active session keeps its lock warm simply by doing anything
# (every SessionStart and every git commit/checkout/rebase attempt refreshes
# it).
set -uo pipefail

MODE="${1:?usage: git-write-guard.sh session-start|gate}"
STALE_SECONDS=1200

lock="$(git rev-parse --git-common-dir 2>/dev/null)/write-lock.json"
[ -z "$lock" ] && exit 0

payload="$(cat)"
sid="$(echo "$payload" | jq -r '.session_id // empty')"
[ -z "$sid" ] && exit 0

if [ "$MODE" = "gate" ]; then
    # Only HEAD/branch-state-mutating subcommands are guarded -- this is the
    # documented incident class ("HEAD moving inside a shared .git"), not
    # "every git invocation." Gating git status/log/diff/show etc. would just
    # break normal read-only work for no safety gain. Parses past leading
    # flags that take a value (-C <path>, -c <key=val>) to find the real
    # subcommand rather than matching the first token literally.
    cmd_str="$(echo "$payload" | jq -r '.tool_input.command // empty')"
    set -- $cmd_str
    subcmd=""
    found_git=0
    while [ "$#" -gt 0 ]; do
        tok="$1"; shift
        if [ "$found_git" -eq 0 ]; then
            [ "$tok" = "git" ] && found_git=1
            continue
        fi
        case "$tok" in
            -C|-c|--git-dir|--work-tree) shift ;;
            -*) ;;
            *) subcmd="$tok"; break ;;
        esac
    done
    is_worktree_cmd=0
    case "$subcmd" in
        commit|checkout|switch|rebase|merge|reset|cherry-pick|revert|pull|am) ;;
        worktree)
            # only add/remove/prune/move mutate the shared registry; list
            # and lock/unlock are read-only-equivalent for this purpose.
            case "${1:-}" in
                add|remove|prune|move) is_worktree_cmd=1 ;;
                *) exit 0 ;;
            esac
            ;;
        *) exit 0 ;;
    esac
fi

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

    # worktree add/remove/prune/move are exempt from the "must already be in
    # a worktree" check below -- they're inherently main-checkout-
    # administrative (worktree add FROM the main checkout is how you GET a
    # worktree in the first place; requiring one first is a bootstrapping
    # deadlock, not a safety property). The lock check above still applies
    # to them, since they do mutate the shared .git/worktrees/ registry.
    if [ "$is_worktree_cmd" -eq 1 ]; then
        exit 0
    fi

    # A live single writer working directly in the main checkout,
    # unworktreed, is still the other half of this week's incident -- HEAD
    # moving under a concurrent read/inspection from anyone else, even a
    # well-behaved second session that's only ever reading.
    gd="$(git rev-parse --absolute-git-dir 2>/dev/null)"
    gc="$(cd "$(git rev-parse --git-common-dir 2>/dev/null)" 2>/dev/null && pwd -P)"
    gd_r="$(cd "$gd" 2>/dev/null && pwd -P)"
    if [ -n "$gd_r" ] && [ "$gd_r" = "$gc" ]; then
        jq -n '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:"Commits/checkouts/rebases must happen in a dedicated worktree, not the shared main checkout -- run EnterWorktree (or git worktree add) first. See CLAUDE.md: start in a worktree, commit+push as your last act."}}'
    fi
    exit 0
fi
