#!/bin/bash
# check-fault-tolerance-issues.sh — fails if any knownOpenTolerance in
# server/faultops cites a GitHub issue that is CLOSED.
#
# What this is for. A knownOpenTolerance downgrades one specific oracle
# violation from a failure to a log line, on the explicit premise that the bug
# is filed and not yet fixed. The moment that issue closes, the premise is
# false and the row stops being debt: it becomes a carve-out that would ABSORB
# the oracle's report if the fix ever regressed. That is strictly worse than no
# tolerance, because the suppression is silent and the row's own expiry date
# gives a false impression of being bounded.
#
# Why issue STATE and not labels. scripts/report-unlisted-security-issues.sh is
# deliberately a report and not a gate, because it keys on the `security` label,
# which this repo applies unreliably (its header documents four confirmed
# misses). That reasoning does NOT transfer here: this script keys on issue
# state, which is not a human convention anyone has to remember to apply. Read
# that script's header before assuming the two are the same kind of signal.
#
# Why this is a separate script and not a Go assertion. Checking issue state
# needs the network. A unit test must not: it would be flaky offline, slow in
# every local run, and would make `go test ./...` depend on a credential. So the
# split is:
#
#   * TestKnownOpenTolerances_CarryIssueAndExpiry (offline, deterministic) —
#     every row has an issue and a parseable expiry, a wildcarded row has a
#     non-empty tables, and an EXPIRED row fails the build.
#   * this script (networked, CI) — every cited issue is still open.
#
# The date check is the backstop for when this script cannot run; the state
# check is the signal that actually matters. Neither replaces the other.
#
# It REFUSES TO RUN rather than passing when it cannot reach the API. A check
# that quietly succeeds when its evidence is unavailable is the opt-in-
# correctness defect this repo keeps relearning: green would mean "no closed
# issues found" when it actually means "nothing was looked at". Pass
# --allow-unverified to downgrade an unreachable API to a warning, for a local
# run where that is what you want; CI never passes it.
#
# Usage:
#   ./scripts/check-fault-tolerance-issues.sh
#   ./scripts/check-fault-tolerance-issues.sh --allow-unverified  # local, no token
#   ./scripts/check-fault-tolerance-issues.sh --self-test         # prove it goes red AND green

set -uo pipefail

REPO="keyorixhq/keyorix"
ALLOW_UNVERIFIED=0
SELF_TEST=0
for arg in "$@"; do
    case "$arg" in
        --allow-unverified) ALLOW_UNVERIFIED=1 ;;
        --self-test) SELF_TEST=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 2 ;;
    esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# issue_state echoes the state of issue $1 ("open"/"closed"), or nothing on a
# failure to reach the API. Separated out so --self-test can stub it.
issue_state() {
    gh api "repos/$REPO/issues/$1" --jq '.state' 2>/dev/null
}

# check_rows reads the TSV on stdin and reports every row whose issue is closed.
# Echoes findings to stdout; returns 1 if anything is wrong, 2 if the API could
# not be reached at all.
check_rows() {
    local label issue expires wild state
    local closed=0 unreachable=0 checked=0
    while IFS=$'\t' read -r label issue expires wild; do
        [ -n "${label:-}" ] || continue
        case "$issue" in
            '#'[0-9]*) ;;
            *)
                echo "  BAD   $label -> issue $issue is not a '#NNNN' reference"
                closed=$((closed + 1))
                continue
                ;;
        esac
        state="$(issue_state "${issue#\#}")"
        if [ -z "$state" ]; then
            echo "  ????  $label -> could not read $issue's state"
            unreachable=$((unreachable + 1))
            continue
        fi
        checked=$((checked + 1))
        if [ "$state" = "closed" ]; then
            echo "  CLOSED $label -> $issue is CLOSED (expiry on the row says $expires, wildcards: $wild)"
            closed=$((closed + 1))
        else
            echo "  ok    $label -> $issue open (expires $expires, wildcards: $wild)"
        fi
    done
    echo "CHECKED=$checked CLOSED=$closed UNREACHABLE=$unreachable"
    if [ "$closed" -gt 0 ]; then return 1; fi
    if [ "$unreachable" -gt 0 ]; then return 2; fi
    return 0
}

if [ "$SELF_TEST" = "1" ]; then
    echo "==> self-test: the check must reject a closed-issue row AND accept an open-issue row"
    rc_total=0

    # Stub issue_state so the self-test needs no network and no credential: the
    # thing under test is the DECISION, not gh's plumbing.
    issue_state() {
        case "$1" in
            9001) echo "open" ;;
            9002) echo "closed" ;;
            9003) echo "" ;; # unreachable
            *) echo "" ;;
        esac
    }

    run_case() {
        local desc="$1" want="$2" rows="$3" got
        printf '%s' "$rows" | check_rows >"$WORK/out" 2>&1
        got=$?
        if [ "$got" != "$want" ]; then
            echo "FAIL: self-test case '$desc' returned $got, want $want" >&2
            sed 's/^/    /' "$WORK/out" >&2
            rc_total=1
        else
            echo "  ok   $desc (returned $got as expected)"
        fi
    }

    run_case "an open issue is accepted" 0 \
        "op/method/error#1	#9001	2099-01-01	-
"
    run_case "a CLOSED issue is rejected" 1 \
        "op/method/error#1	#9002	2099-01-01	-
"
    run_case "a closed issue is rejected even alongside open ones" 1 \
        "a/m/error#1	#9001	2099-01-01	-
b/m/error#1	#9002	2099-01-01	-
"
    run_case "an unreachable issue is NOT silently accepted" 2 \
        "op/method/error#1	#9003	2099-01-01	-
"
    run_case "a malformed issue reference is rejected" 1 \
        "op/method/error#1	n/a	2099-01-01	-
"

    if [ "$rc_total" = "0" ]; then
        echo "ok: self-test passed — the check goes red on a closed/unreadable/malformed row and green on an open one"
    fi
    exit "$rc_total"
fi

echo "==> dumping knownOpenTolerances"
DUMP="$WORK/tolerances.tsv"
if ! KEYORIX_TOLERANCE_DUMP="$DUMP" go test ./server/faultops/ \
    -run '^TestDumpKnownOpenTolerances$' -count=1 >"$WORK/dump.log" 2>&1; then
    echo "FAIL: could not run the tolerance dump test" >&2
    sed 's/^/    /' "$WORK/dump.log" >&2
    exit 1
fi
if [ ! -f "$DUMP" ]; then
    # The dump test SKIPS when its env var is unset, and a skip exits zero. If
    # the file is missing, the test did not actually run -- treat that as a
    # failure, never as "no rows to check".
    echo "FAIL: the dump test exited zero but wrote no file to $DUMP — it was probably skipped." >&2
    echo "      An empty result must not read as 'no tolerances to check'." >&2
    sed 's/^/    /' "$WORK/dump.log" >&2
    exit 1
fi

ROWS="$(wc -l <"$DUMP" | tr -d ' ')"
echo "==> checking $ROWS tolerance row(s) against $REPO issue state"
if [ "$ROWS" = "0" ]; then
    echo "ok: knownOpenTolerances is empty — nothing to check (and that is the goal state)"
    exit 0
fi

check_rows <"$DUMP"
rc=$?

case "$rc" in
    0) echo "ok: every knownOpenTolerance cites an OPEN issue" ;;
    1)
        cat >&2 <<'MSG'

FAIL: at least one knownOpenTolerance cites a CLOSED issue.

A tolerance exists on the premise that its bug is filed and NOT YET FIXED. Once
the issue closes that premise is false, and the row stops being tracked debt --
it becomes a silent carve-out that would absorb the oracle's report if the fix
regressed.

Re-triage each row above; do not just move its expiry date:

  1. The bug is fixed  -> DELETE the row. TestKnownOpenTolerances_AreLoadBearing
     should already be reporting it dead; if it is not, the row is suppressing
     something OTHER than what it claims, which is its own finding.
  2. The behaviour is intended -> move it to oracleAByDesignErrors with a design
     citation and a proving test.
  3. The issue was closed in error -> reopen it, or re-file and update the row.
MSG
        ;;
    2)
        if [ "$ALLOW_UNVERIFIED" = "1" ]; then
            echo
            echo "WARNING: some issue states could not be read, and --allow-unverified was passed."
            echo "         This run proves nothing about those rows."
            rc=0
        else
            cat >&2 <<'MSG'

FAIL: could not read at least one issue's state (no credential, rate limit, or
network).

This is deliberately a failure and not a pass. Green here would mean "no closed
issues found" when it actually means "nothing was looked at" -- the
opt-in-correctness shape this repo keeps relearning. The offline backstop is
TestKnownOpenTolerances_CarryIssueAndExpiry's expiry check, which still runs.

For a local run where an unverified result is what you want:
  ./scripts/check-fault-tolerance-issues.sh --allow-unverified
MSG
        fi
        ;;
esac

exit "$rc"
