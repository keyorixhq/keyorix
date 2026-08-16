#!/usr/bin/env bash
# Sends an ntfy.sh summary for one package's mutation-testing run, and — only
# when test efficacy regressed versus the LAST recorded run for that same
# package — escalates to a high-priority alert and opens/updates a GitHub
# issue listing the newly-surviving mutants. Mirrors notify-on-crash.sh's
# dedup-by-marker-file pattern (see scripts/fuzzing/), but for "test quality
# got worse" rather than "fuzzer found a crash": a LIVED mutant isn't
# necessarily a bug by itself, so this deliberately does NOT open an issue on
# every run, only when the signal moves in the wrong direction, and never
# re-alerts for a regression already reported and still unresolved.
set -euo pipefail

LABEL="${1:?package label, e.g. core}"
SUMMARY_JSON="${2:?path to the current run summary JSON}"
PREV_SUMMARY_JSON="${3:-}"

: "${MUTATION_STATE_DIR:?}"
: "${MUTATION_EFFICACY_DROP_THRESHOLD:=5}"

# Scratch file for curl's --config (-K) file, keeping the NTFY_TOPIC URL (the
# bearer secret protecting the ntfy.sh channel) out of curl's argv -- see
# scripts/fuzzing/heartbeat.sh for the identical rationale.
ntfy_curl_cfg=""
cleanup_ntfy_curl_cfg() {
  # `if`, not `[[ ]] && rm`: this runs as an EXIT trap, and this script exits
  # 0 well before ntfy_curl_cfg is ever set (NTFY_TOPIC is optional here,
  # unlike heartbeat.sh where it's mandatory) -- a short-circuited `&&`
  # returning false would make the trap itself return nonzero, which bash
  # then reports as THIS SCRIPT's exit status, silently turning an intended
  # `exit 0` into an observed exit 1.
  if [[ -n "$ntfy_curl_cfg" ]]; then
    rm -f "$ntfy_curl_cfg"
  fi
}
trap cleanup_ntfy_curl_cfg EXIT

efficacy="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("test_efficacy_pct"))' "$SUMMARY_JSON")"
total="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("total_mutants"))' "$SUMMARY_JSON")"
lived_count="$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1])).get("lived", [])))' "$SUMMARY_JSON")"
not_covered="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1])).get("counts", {}).get("NOT COVERED", 0))' "$SUMMARY_JSON")"

regressed=false
regression_body=""
if [[ -n "$PREV_SUMMARY_JSON" && -f "$PREV_SUMMARY_JSON" ]]; then
  prev_efficacy="$(python3 -c 'import json, sys; e = json.load(open(sys.argv[1])).get("test_efficacy_pct"); print(e if e is not None else -1)' "$PREV_SUMMARY_JSON")"
  # Values are passed as argv rather than interpolated into the Python
  # source string, so a value containing a quote/backslash can't break out
  # of a string literal and get read as Python code.
  if python3 -c '
import sys


def parse_num(s):
    return None if s == "None" else float(s)


eff = parse_num(sys.argv[1])
prev = parse_num(sys.argv[2])
thresh = parse_num(sys.argv[3])
sys.exit(0 if (prev is not None and prev >= 0 and eff is not None and prev - eff >= thresh) else 1)
' "$efficacy" "$prev_efficacy" "$MUTATION_EFFICACY_DROP_THRESHOLD"; then
    regressed=true
    regression_body="$(python3 - "$SUMMARY_JSON" "$PREV_SUMMARY_JSON" <<'PYEOF'
import json, sys
cur = json.load(open(sys.argv[1]))
prev = json.load(open(sys.argv[2]))
prev_locs = {(m["file"], m["line"], m["column"]) for m in prev.get("lived", [])}
new_lived = [m for m in cur.get("lived", []) if (m["file"], m["line"], m["column"]) not in prev_locs]
print(f"Efficacy dropped from {prev.get('test_efficacy_pct')}% to {cur.get('test_efficacy_pct')}%.")
print()
print(f"{len(new_lived)} newly-surviving mutant(s):")
for m in new_lived[:30]:
    print(f"- `{m['file']}:{m['line']}` ({m['type']})")
if len(new_lived) > 30:
    print(f"- ... and {len(new_lived) - 30} more")
PYEOF
)"
  fi
fi

status_line="mutation-testing ($LABEL): $total mutants, ${efficacy}% efficacy, $lived_count lived, $not_covered not covered"
echo "$status_line"

# ntfy.sh notification (optional -- skip if NTFY_TOPIC is unset or empty)
if [[ -n "${NTFY_TOPIC:-}" ]]; then
  ntfy_curl_cfg="$(mktemp)"
  chmod 600 "$ntfy_curl_cfg"
  printf 'url = "%s"\n' "$NTFY_TOPIC" >"$ntfy_curl_cfg"

  if $regressed; then
    title="keyorix mutation testing ($LABEL): efficacy regressed"
    priority="high"
    tags="rotating_light"
    body="$status_line

$regression_body"
  else
    title="keyorix mutation testing ($LABEL): $efficacy% efficacy"
    priority="default"
    tags="test_tube"
    body="$status_line"
  fi

  curl -fsS \
    -K "$ntfy_curl_cfg" \
    -H "Title: $title" \
    -H "Priority: $priority" \
    -H "Tags: $tags" \
    -d "$body" \
    >/dev/null || echo "notify-summary: ntfy push failed for $LABEL" >&2
fi

if ! $regressed; then
  exit 0
fi

# GitHub issue -- only on a real regression, deduped so an unresolved
# regression doesn't get a fresh issue every week.
regression_hash="$(printf '%s' "$regression_body" | sha256sum | cut -c1-16)"
marker="$MUTATION_STATE_DIR/notified-$LABEL-$regression_hash"
if [[ -f "$marker" ]]; then
  exit 0 # already reported this exact regression
fi

gh_err="$MUTATION_STATE_DIR/gh-error-$LABEL-$regression_hash.log"
issue_title="mutation testing ($LABEL): efficacy regressed"
issue_body="## Mutation-testing efficacy regression: \`$LABEL\`

$regression_body

Each surviving mutant above is a line the test suite executes but wouldn't
notice if its logic were subtly wrong. See \`.semgrep/RULE-MINING-PROCESS.md\`
and \`scripts/mutation-testing/README.md\` for context on why this is
tracked."

issue_notified=false
existing_issue="$(gh issue list --search "in:title \"$issue_title\"" --state open --json number --jq '.[0].number' 2>>"$gh_err" || true)"
if [[ -n "$existing_issue" ]]; then
  if gh issue comment "$existing_issue" --body "**Still regressed ($(date -u +%FT%TZ)):**

$regression_body" 2>>"$gh_err"; then
    issue_notified=true
  fi
else
  if gh issue create --title "$issue_title" --body "$issue_body" 2>>"$gh_err"; then
    issue_notified=true
  fi
fi

if $issue_notified; then
  touch "$marker"
else
  echo "notify-summary: GitHub issue notification failed for $LABEL — see $gh_err" >&2
fi
