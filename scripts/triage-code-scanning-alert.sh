#!/bin/bash
# triage-code-scanning-alert.sh -- dismisses a code-scanning alert ONLY after
# verifying it is the known Semgrep --config=auto false-positive quirk
# documented in .github/workflows/semgrep.yml.
#
# Why this exists: alerts #816/#817 (dynamic-urllib-use-detected, in
# scripts/memory-measurement/{load_driver,container_env}.py) were "fixed" by
# adding a nosemgrep comment -- which shifted the flagged lines by two,
# marked the ORIGINAL alerts fixed (they no longer existed at those line
# numbers), and opened #819/#820 as brand-new alerts at the new lines. The
# finding never went away; it moved. Code-scanning alerts are anchored to a
# file and line -- editing near one you cannot suppress is a treadmill, and
# another edit would have produced #821/#822.
#
# The workflow's own instruction was already correct (rerun the single file
# with the same config; if clean and the nosemgrep is there, dismiss, don't
# re-suppress) but was not being followed, because doing it by hand is
# fiddly and re-suppressing LOOKS like fixing. This script makes the
# correct path the only path: it is structurally impossible to reach the
# dismiss API call without both checks below having actually run and
# passed in this exact invocation -- there is no flag or code path that
# skips them.
#
# Usage: ./scripts/triage-code-scanning-alert.sh <alert-number>
#   Requires: gh (authenticated), jq, semgrep. Run from anywhere -- resolves
#   the repo root and target repo itself.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO="${GH_REPO:-$(gh repo view --json nameWithOwner -q .nameWithOwner)}"

die()  { echo "REFUSED: $*" >&2; exit 1; }
note() { echo "  $*"; }

N="${1:?usage: triage-code-scanning-alert.sh <alert-number>}"
case "$N" in
    ''|*[!0-9]*) die "alert number must be a positive integer, got '$N'" ;;
esac

echo "==> Fetching alert #$N from $REPO"
alert_json="$(gh api "repos/$REPO/code-scanning/alerts/$N")"

state="$(jq -r '.state' <<<"$alert_json")"
rule_id="$(jq -r '.rule.id' <<<"$alert_json")"
path="$(jq -r '.most_recent_instance.location.path' <<<"$alert_json")"
start_line="$(jq -r '.most_recent_instance.location.start_line' <<<"$alert_json")"

if [ -z "$rule_id" ] || [ "$rule_id" = "null" ]; then
    die "could not read rule id from the alert response -- refusing to guess"
fi

note "state=$state rule=$rule_id path=$path line=$start_line"

# --- Gate 1: must be open. A dismissed/fixed alert has nothing to verify. ---
if [ "$state" != "open" ]; then
    die "alert #$N is '$state', not 'open' -- nothing to triage. If it shows" \
        "'fixed' at a DIFFERENT line than you expected, the finding likely" \
        "moved (see this script's own header) -- check for a newer alert" \
        "number on the same rule+file before assuming this one is really gone."
fi

if [ ! -f "$REPO_ROOT/$path" ]; then
    die "alert #$N names '$path', which does not exist in this checkout" \
        "at $REPO_ROOT -- refusing to scan a file that isn't there."
fi

# --- Gate 2: the documented single-file rerun, same config as the advisory scan. ---
echo "==> Running the documented single-file rerun (same config as the advisory scan)"
semgrep_version="$(semgrep --version 2>/dev/null | tail -1)"
rerun_json="$(cd "$REPO_ROOT" && semgrep scan --config=auto --config=.semgrep/keyorix-rules.yml --json "$path" 2>/dev/null)" \
    || die "the single-file semgrep rerun itself failed to run -- cannot treat silence as evidence of anything"

error_count="$(jq '.errors | length' <<<"$rerun_json")"
if [ "$error_count" -ne 0 ]; then
    die "the single-file rerun reported $error_count scan error(s) -- a rerun" \
        "that didn't complete cleanly is not trustworthy evidence of zero" \
        "findings. Errors: $(jq -c '.errors' <<<"$rerun_json")"
fi

# Match on rule id AND the alert's own line -- not "is this rule id absent
# from the whole file", which would wrongly clear a genuinely-still-broken
# instance of the same rule sitting at a different, unrelated line in the
# same file.
still_firing="$(jq --arg rule "$rule_id" --argjson line "$start_line" \
    '[.results[] | select(.check_id == $rule and .start.line == $line)] | length' \
    <<<"$rerun_json")"

rerun_clean=0
if [ "$still_firing" -eq 0 ]; then
    rerun_clean=1
    note "rerun: 0 findings for $rule_id at $path:$start_line"
else
    note "rerun: STILL FIRES -- $still_firing finding(s) for $rule_id at $path:$start_line"
fi

# --- Gate 3: the line must carry a nosemgrep matching the EXACT rule id. ---
# Accepts `# nosemgrep: <rule>` or `// nosemgrep: <rule>`, optionally one of
# several comma-separated ids, optionally followed by ` -- reason` text.
# Rejects a bare `# nosemgrep` (no id at all) and a suppression naming a
# DIFFERENT rule -- both are exactly the shape that would make this script
# dismiss the wrong thing if it only checked "is there a nosemgrep here".
line_text="$(sed -n "${start_line}p" "$REPO_ROOT/$path")"
rule_id_escaped="$(printf '%s' "$rule_id" | sed 's/[.[\*^$/]/\\&/g')"
suppression_present=0
if printf '%s' "$line_text" | grep -qE "(#|//)[[:space:]]*nosemgrep:[[:space:]]*([A-Za-z0-9_.,\ -]*,)?${rule_id_escaped}(,|[[:space:]]|--|$)"; then
    suppression_present=1
    note "line $start_line carries a nosemgrep matching $rule_id"
else
    note "line $start_line does NOT carry a nosemgrep matching $rule_id exactly"
    note "  actual line: $line_text"
fi

# --- Decide: BOTH gates, never either alone. ---
if [ "$rerun_clean" -ne 1 ] || [ "$suppression_present" -ne 1 ]; then
    echo
    die "verification did not fully pass (rerun_clean=$rerun_clean" \
        "suppression_present=$suppression_present) -- both must hold." \
        "This is either a real, still-live finding, or a suppression that" \
        "doesn't name this exact rule. Not dismissing. If the finding is" \
        "real, fix it in code -- see CLAUDE.md's Code-scanning alerts note."
fi

echo "==> Both gates passed. Dismissing #$N as a false positive."

# --- Comment: pointer to the note, semgrep version, finding count, rule id. ---
# dismissed_comment is capped at 280 chars server-side (422 if exceeded,
# verified 2026-09-08) -- some real rule ids (dynamic-urllib-use-detected is
# ~100 chars alone) push a fully-spelled-out comment past that on their own,
# so the pointer to the workflow note is placed FIRST, not last, so it's
# what survives if truncation is still needed for an unusually long
# rule id + path combination -- never let the cap be why a sound
# verification fails to record itself.
comment="False positive (see .github/workflows/semgrep.yml): semgrep $semgrep_version single-file rerun, same config, 0 findings for $rule_id at $path:$start_line. Matching nosemgrep present."
if [ "${#comment}" -gt 280 ]; then
    comment="${comment:0:277}..."
fi
note "comment (${#comment} chars): $comment"

gh api --method PATCH "repos/$REPO/code-scanning/alerts/$N" \
    -f state=dismissed \
    -f dismissed_reason='false positive' \
    -f dismissed_comment="$comment" \
    > /dev/null

echo "==> Dismissed #$N."
