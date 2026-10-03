#!/bin/bash
# git-write-guard_test.sh -- red/green proof that git-write-guard.sh's
# write-lock and worktree-only checks apply to the main checkout and its
# worktrees, and ONLY those, never to an independent `git clone` (CI-1,
# 2026-10-03). Invokes the real hook script as a subprocess for each case,
# with the test's own `cd` standing in for the fixed cwd the PreToolUse
# harness always launches the hook from -- git-write-guard.sh resolves
# "the main checkout" from its own ambient process cwd, so the harness's
# real invocation pattern (always launched from the one shared project
# root) only works if this test replicates that exactly, not by sourcing
# the script or passing a -C on the invocation of the hook itself.
set -euo pipefail

HOOK="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/git-write-guard.sh"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

MAIN="$WORKDIR/main"
mkdir -p "$MAIN"
git -C "$MAIN" init -q -b main
git -C "$MAIN" config user.email test@example.com
git -C "$MAIN" config user.name test
git -C "$MAIN" commit -q --allow-empty -m init

WT="$WORKDIR/worktree"
git -C "$MAIN" worktree add -q "$WT" -b wt-branch >/dev/null

CLONE="$WORKDIR/clone"
git clone -q "$MAIN" "$CLONE"

pass=0
fail=0

# Seed $MAIN's write-lock.json as held by a DIFFERENT, fresh session --
# simulates "another session claimed write access to this repo moments
# ago" without waiting out any real clock.
claim_main_lock() {
    gc="$(git -C "$MAIN" rev-parse --path-format=absolute --git-common-dir)"
    jq -n --arg sid "other-session" --argjson ts "$(date -u +%s)" \
        '{sessionId:$sid, claimedAtEpoch:$ts}' > "$gc/write-lock.json"
}

# Runs the hook exactly as the PreToolUse harness does: cwd = the fixed
# main-checkout root (first arg), stdin = the JSON payload the harness
# feeds it, built from a session id (second arg) and a raw command string
# (third arg, containing its own `-C <target>` -- that's what tells the
# hook which repo this particular git invocation actually targets).
run_gate() {
    local cwd="$1" sid="$2" cmd="$3"
    (cd "$cwd" && jq -n --arg sid "$sid" --arg cmd "$cmd" \
        '{session_id:$sid, tool_input:{command:$cmd}}' | bash "$HOOK" gate)
}

expect_deny() {
    local desc="$1" out="$2"
    if [ -n "$out" ] && echo "$out" | jq -e '.hookSpecificOutput.permissionDecision == "deny"' >/dev/null 2>&1; then
        echo "PASS (denied as expected): $desc"
        pass=$((pass + 1))
    else
        echo "FAIL (expected deny): $desc -- got: ${out:-<empty, i.e. allowed>}"
        fail=$((fail + 1))
    fi
}

expect_allow() {
    local desc="$1" out="$2"
    if [ -z "$out" ]; then
        echo "PASS (allowed as expected): $desc"
        pass=$((pass + 1))
    else
        echo "FAIL (expected allow / no output): $desc -- got: $out"
        fail=$((fail + 1))
    fi
}

claim_main_lock

# (a) a second session, committing directly in the main checkout: blocked
# by the write-lock -- unchanged behaviour, still "one writer per .git".
out_a="$(run_gate "$MAIN" "my-session" "git -C $MAIN commit -q -m x --allow-empty")"
expect_deny "(a) second session in main checkout" "$out_a"

# (b) a second session, committing in a worktree OF main: blocked too --
# a linked worktree shares the main checkout's git-common-dir (and so its
# write-lock.json) by git's own design, so this is the same lock as (a),
# not a different one.
out_b="$(run_gate "$MAIN" "my-session" "git -C $WT commit -q -m x --allow-empty")"
expect_deny "(b) second session in a worktree of main" "$out_b"

# (c) an INDEPENDENT clone: allowed, even though main's lock is actively
# held by someone else right now -- this is the documented design the
# header has always claimed and the implementation (pre-fix) did not
# deliver: a clone's git-common-dir differs from main's, so it must never
# even look at main's lock file.
out_c="$(run_gate "$MAIN" "my-session" "git -C $CLONE commit -q -m x --allow-empty")"
expect_allow "(c) independent clone exempt from main's lock" "$out_c"

echo "---"
echo "pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
