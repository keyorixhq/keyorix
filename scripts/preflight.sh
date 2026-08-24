#!/bin/bash
# preflight.sh — base-is-current check. Run before starting a PR series.
#
# Confirms origin/main is an ancestor of HEAD, i.e. this branch was cut from
# (or has since merged) the current tip of main, not a stale snapshot. Stale
# branch state has cost the G80 remediation campaign real work three times —
# see docs/g80-remediation-notes.md.
set -e

git fetch origin main --quiet

if git merge-base --is-ancestor origin/main HEAD; then
    echo "ok: origin/main is an ancestor of HEAD — branch base is current"
else
    echo "FAIL: origin/main is NOT an ancestor of HEAD — this branch was cut from a stale base."
    echo "Rebase or merge origin/main before starting a PR series."
    exit 1
fi
