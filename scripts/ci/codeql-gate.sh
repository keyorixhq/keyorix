#!/usr/bin/env bash
# CodeQL merge-queue gate (CODEQL-QUEUE-1).
#
# In the merge queue codeql.yml analyses with `upload: never`: the SARIF upload
# ran after GitHub had already deleted the gh-readonly-queue/* branch and failed
# with "ref ... not found in this repository" (~40 queue entries a day). With no
# upload there are no code-scanning results on the merge group, so this script
# is the gate: it reads the SARIF files the analysis wrote to disk and fails when
# a HIGH-or-worse result (rule security-severity >= 7.0, GitHub's own "high"
# threshold) is not already a known code-scanning alert on main: open, or
# dismissed.
#
# Dismissed = accepted risk. A human reviewed the alert in the Security tab and
# dismissed it (won't fix / false positive); the analysis still writes such a
# finding into the SARIF on every run, so treating only state=open as known made
# every dismissed finding "new" and failed nearly every queue entry (18 Oct).
# Only state=fixed alerts are ignored: a fixed finding that reappears is new.
#
# "Already known on main" is matched by (rule id, file path), not by line: a
# line-exact match would call every pre-existing alert "new" whenever a queue
# entry shifts the line. The consequence is that a SECOND instance of a known
# rule in a file that already has an alert is not caught here; it is caught
# after merge, when the push-to-main run uploads and the new alert appears in
# the Security tab. Everything else (a new rule, or an old rule in a new file)
# fails the queue entry.
#
# Diagnosability (CODEQL-PR-GATE-1): for every NEW high result the log prints
# the rule id, security-severity, file:line, the message text and the first
# step of the code flow (the taint source; relatedLocations[0] when the result
# has no codeFlows), as plain lines AND as an ::error annotation whose text
# carries file:line itself (an annotation's file= property is shown only in the
# Annotations panel, not in the log, which is how a whole hour went into finding
# the cause of the 23 Oct queue failures). The same table goes to
# $GITHUB_STEP_SUMMARY when it is set. Known results are listed too, so a pass
# can be checked against the alert list.
#
# Fails closed: unreadable SARIF, no SARIF at all, or an alerts-API failure with
# high results present is an error, never a pass.
#
# Usage: codeql-gate.sh <sarif-dir>
# Env:   GH_TOKEN, REPO (owner/name) -- to read main's open and dismissed alerts.
#        GITHUB_STEP_SUMMARY -- optional; a Markdown summary is appended to it.
#        GATE_RETRY_SLEEP -- test hook: seconds per retry step (default 5).
#        GATE_BASELINE_TSV -- test hook: a file of "ruleId<TAB>path" lines used
#        instead of the API.
set -euo pipefail

dir=${1:?usage: codeql-gate.sh <sarif-dir>}
threshold=7.0
summary_file=${GITHUB_STEP_SUMMARY:-}

# summary appends Markdown to the job summary when the runner provides one.
summary() {
  if [ -n "$summary_file" ]; then
    printf '%s\n' "$@" >> "$summary_file"
  fi
}

# Workflow-command escaping (actions/toolkit): data needs % CR LF escaped, a
# property value additionally : and ,.
esc_data() {
  local s=$1
  s=${s//'%'/'%25'}
  s=${s//$'\r'/'%0D'}
  s=${s//$'\n'/'%0A'}
  printf '%s' "$s"
}
esc_prop() {
  local s
  s=$(esc_data "$1")
  s=${s//':'/'%3A'}
  s=${s//','/'%2C'}
  printf '%s' "$s"
}

# A Markdown table cell: no pipes, no raw HTML, no line breaks.
md_cell() {
  local s=$1
  s=${s//'|'/'\|'}
  s=${s//'<'/'&lt;'}
  s=${s//'>'/'&gt;'}
  printf '%s' "$s"
}

shopt -s nullglob
files=("$dir"/*.sarif)
if [ "${#files[@]}" -eq 0 ]; then
  echo "codeql-gate: no .sarif files in $dir -- the analysis wrote nothing; failing closed" >&2
  summary "### CodeQL gate: FAILED (fail-closed)" "" "No .sarif file in \`$dir\`: the analysis wrote nothing."
  exit 1
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
: > "$work/high.tsv"

for f in "${files[@]}"; do
  # rule id -> security-severity, over driver rules and extension rules; one
  # TSV row per result at or above the threshold: ruleId, path, line,
  # severity, message (first line, at most 300 characters), first code-flow
  # step ("path:line: text", or "-"), SARIF category. CodeQL's "[text](N)"
  # placeholder links become plain text. Every field is non-empty
  # (tab is IFS whitespace, so an empty field would shift the ones after it).
  if ! jq -r --argjson thr "$threshold" --arg file "${f##*/}" '
    def oneline: (. // "") | tostring | gsub("[\t\r\n]+"; " ")
      | gsub("\\[(?<t>[^\\]]*)\\]\\([0-9]+\\)"; .t)
      | if length > 300 then .[0:300] + "..." else . end;
    def nonempty: if . == null or . == "" then "-" else . end;
    def loc: (.physicalLocation.artifactLocation.uri // "?") + ":"
             + ((.physicalLocation.region.startLine // 0) | tostring)
             + (if (.message.text // "") != "" then ": " + (.message.text | oneline) else "" end);
    .runs[]
    | (.automationDetails.id // $file) as $cat
    | ([ (.tool.driver.rules // [])[], ((.tool.extensions // [])[] | (.rules // [])[]) ]
       | map({key: .id, value: ((.properties["security-severity"] // "0") | tonumber)})
       | from_entries) as $sev
    | (.results // [])[]
    | select(($sev[.ruleId] // 0) >= $thr)
    | [.ruleId,
       (.locations[0].physicalLocation.artifactLocation.uri // "?"),
       ((.locations[0].physicalLocation.region.startLine // 0) | tostring),
       (($sev[.ruleId]) | tostring),
       ((.message.text // "" | split("\n")[0] | oneline) | nonempty),
       ((if .codeFlows[0].threadFlows[0].locations[0].location then
           "source " + (.codeFlows[0].threadFlows[0].locations[0].location | loc)
           + " (step 1 of " + (.codeFlows[0].threadFlows[0].locations | length | tostring) + ")"
         elif .relatedLocations[0] then
           "related " + (.relatedLocations[0] | loc)
         else "-" end) | nonempty),
       ($cat | oneline | nonempty)]
    | @tsv' "$f" >> "$work/high.tsv"; then
    echo "codeql-gate: cannot read $f as SARIF; failing closed" >&2
    summary "### CodeQL gate: FAILED (fail-closed)" "" "\`${f##*/}\` is not readable SARIF."
    exit 1
  fi
done

total=$(wc -l < "$work/high.tsv" | tr -d ' ')
echo "codeql-gate: ${#files[@]} SARIF file(s), $total result(s) with security-severity >= $threshold"
if [ "$total" -eq 0 ]; then
  summary "### CodeQL gate: passed" "" "No result with security-severity >= $threshold."
  exit 0
fi

if [ -n "${GATE_BASELINE_TSV:-}" ]; then
  cp "$GATE_BASELINE_TSV" "$work/known.tsv"
else
  : "${REPO:?REPO is required}"
  : > "$work/known.tsv"
  # Both states count as "known on main": open = tracked, dismissed = a human
  # already decided (won't fix / false positive). fixed alerts do not count.
  for state in open dismissed; do
    ok=""
    for attempt in 1 2 3; do
      if gh api --paginate "repos/$REPO/code-scanning/alerts?state=$state&ref=refs/heads/main&per_page=100" \
        --jq '.[] | [.rule.id, .most_recent_instance.location.path] | @tsv' > "$work/alerts-$state.tsv"; then
        ok=1
        break
      fi
      echo "codeql-gate: alerts API ($state) attempt $attempt failed" >&2
      sleep $((attempt * ${GATE_RETRY_SLEEP:-5}))
    done
    if [ -z "$ok" ]; then
      echo "codeql-gate: cannot read main's $state alerts; failing closed" >&2
      summary "### CodeQL gate: FAILED (fail-closed)" "" "$total high-severity result(s), but main's $state code-scanning alerts could not be read."
      exit 1
    fi
    cat "$work/alerts-$state.tsv" >> "$work/known.tsv"
  done
fi

: > "$work/new.tsv"
: > "$work/old.tsv"
while IFS=$'\t' read -r rule path line sev msg flow cat; do
  if grep -qxF "$(printf '%s\t%s' "$rule" "$path")" "$work/known.tsv"; then
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rule" "$path" "$line" "$sev" "$msg" "$flow" "$cat" >> "$work/old.tsv"
  else
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$rule" "$path" "$line" "$sev" "$msg" "$flow" "$cat" >> "$work/new.tsv"
  fi
done < "$work/high.tsv"
new=$(wc -l < "$work/new.tsv" | tr -d ' ')
old=$(wc -l < "$work/old.tsv" | tr -d ' ')

while IFS=$'\t' read -r rule path line sev msg flow cat; do
  echo "codeql-gate: known on main (open or dismissed): $rule (security-severity $sev) at $path:$line [$cat]"
done < "$work/old.tsv"

n=0
while IFS=$'\t' read -r rule path line sev msg flow cat; do
  n=$((n + 1))
  echo "codeql-gate: NEW high-severity result $n of $new [$cat]"
  echo "  rule:     $rule (security-severity $sev)"
  echo "  location: $path:$line"
  echo "  message:  $msg"
  echo "  flow:     $flow"
  echo "::error file=$(esc_prop "$path"),line=$(esc_prop "$line"),title=$(esc_prop "CodeQL $rule (new on this change)")::$(esc_data "CodeQL high-severity result $rule (security-severity $sev) at $path:$line is not an open or dismissed alert on main. $msg -- flow: $flow")"
done < "$work/new.tsv"

table_rows() {
  while IFS=$'\t' read -r rule path line sev msg flow cat; do
    summary "| \`$(md_cell "$rule")\` | $sev | \`$(md_cell "$path:$line")\` | $(md_cell "$msg") | $(md_cell "$flow") |"
  done < "$1"
}

if [ "$new" -ne 0 ]; then
  summary "### CodeQL gate: FAILED -- $new new high-severity result(s)" "" \
    "Not an open or dismissed code-scanning alert on main (matched by rule id + file). Fix it in code; a suspected false positive is a coordinator decision (an alert can be dismissed only once it exists on main)." "" \
    "| Rule | Severity | Location | Message | Flow starts at |" "|---|---|---|---|---|"
  table_rows "$work/new.tsv"
else
  summary "### CodeQL gate: passed" "" "Every high-severity result is already an open or dismissed alert on main."
fi
if [ "$old" -ne 0 ]; then
  summary "" "<details><summary>$old high-severity result(s) already known on main</summary>" "" \
    "| Rule | Severity | Location | Message | Flow starts at |" "|---|---|---|---|---|"
  table_rows "$work/old.tsv"
  summary "" "</details>"
fi

if [ "$new" -ne 0 ]; then
  exit 1
fi
echo "codeql-gate: every high-severity result is already an open or dismissed alert on main"
