#!/bin/bash
# validate-budget.sh — checks scripts/fuzzing/targets.d/BUDGET.tsv for the
# three ways it can silently go stale: a priority line naming a target file
# that no longer exists (renamed/removed), an invalid priority value (typo),
# or a duplicate target name (copy-paste mistake). Fast, no fuzzing, no long
# runs -- suitable for CI once fuzz-harness reads targets.d/ directly (see
# docs/fuzzing/continuous-rig.md's HANDOFF section for why it isn't wired
# into ci.yml yet).
#
# Usage: scripts/fuzzing/validate-budget.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGETS_D="$REPO_ROOT/scripts/fuzzing/targets.d"
BUDGET="$TARGETS_D/BUDGET.tsv"

fail=0
die() { echo "FAIL: $*" >&2; fail=1; }

if [ ! -f "$BUDGET" ]; then
    echo "FAIL: $BUDGET not found" >&2
    exit 1
fi

rows=$(grep -vE '^[[:space:]]*(#|$)' "$BUDGET" || true)
if [ -z "$rows" ]; then
    echo "ok: $BUDGET has no priority overrides (every target defaults to medium)"
    exit 0
fi

seen=""
while IFS=$'\t' read -r name priority; do
    [ -z "${name:-}" ] && continue
    if [ ! -f "$TARGETS_D/$name" ]; then
        die "BUDGET.tsv names '$name', which does not exist in targets.d/ (stale entry after a rename/removal?)"
    fi
    case "${priority:-}" in
        high|medium|low) ;;
        *) die "BUDGET.tsv: '$name' has invalid priority '${priority:-<empty>}' (must be high, medium, or low)" ;;
    esac
    if grep -qxF "$name" <<<"$seen"; then
        die "BUDGET.tsv: '$name' appears more than once"
    fi
    seen="$seen$name
"
done <<<"$rows"

[ "$fail" -eq 0 ] || exit 1
echo "ok: $(echo "$rows" | wc -l | tr -d ' ') priority override(s) in BUDGET.tsv, all valid"
