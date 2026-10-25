#!/usr/bin/env bash
# failfast-cancel.sh <failed-job>
#
# Merge-queue fail fast (CI-FAILFAST-1). Run by .github/workflows/failfast-cancel.yml
# right after a ci.yml job whose failure already fails the round (a required check, or
# a job a required aggregator such as build-and-test fails on). The round cannot pass
# any more, so this cancels every workflow run still queued or in progress for the
# same merge-group commit (ci.yml itself, CodeQL, ...), instead of letting ~18 test-suite
# legs keep their runners for another 20-40 minutes. The current run is cancelled
# last, after its siblings, because that cancel also stops this job.
#
# Scope: only runs whose event is merge_group AND whose head_sha is this run's
# GITHUB_SHA. A merge-group commit belongs to exactly one queue entry, so no other
# entry, PR or main run can be touched.
#
# Never fails its caller: a cancel that cannot be sent only loses the saving, and the
# round is already red. Every target and every API error is logged.
#
# Test hook: FAILFAST_RUNS_JSON=<file> reads the run list from a file and
# FAILFAST_DRY_RUN=1 prints the cancels instead of sending them
# (scripts/ci/failfast_cancel_test.go runs it against a recorded API response).
set -uo pipefail

failed_job=${1:-unknown}
repo=${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}
run_id=${GITHUB_RUN_ID:?GITHUB_RUN_ID is not set}
sha=${GITHUB_SHA:?GITHUB_SHA is not set}

echo "fail fast: ${failed_job} failed, so this merge-queue round (${sha}) cannot pass; cancelling its other runs"

if [ -n "${FAILFAST_RUNS_JSON:-}" ]; then
  runs=$(cat "${FAILFAST_RUNS_JSON}") || { echo "::warning::fail fast: cannot read ${FAILFAST_RUNS_JSON}"; exit 0; }
elif ! runs=$(gh api "repos/${repo}/actions/runs?event=merge_group&head_sha=${sha}&per_page=100"); then
  echo "::warning::fail fast: listing the runs of ${sha} failed; cancelling only this run"
  runs='{"workflow_runs":[]}'
fi

# Siblings first (still running, same commit, merge_group, not this run), then this run.
if ! siblings=$(jq -r --arg sha "${sha}" --argjson self "${run_id}" '
    .workflow_runs[]
    | select(.event == "merge_group" and .head_sha == $sha and .status != "completed" and .id != $self)
    | "\(.id) \(.name)"' <<<"${runs}"); then
  echo "::warning::fail fast: unexpected run list; cancelling only this run"
  siblings=""
fi

cancel() {
  local id=$1 name=$2
  if [ -n "${FAILFAST_DRY_RUN:-}" ]; then
    echo "would cancel ${id} ${name}"
    return
  fi
  if gh api -X POST "repos/${repo}/actions/runs/${id}/cancel" >/dev/null; then
    echo "cancelled ${id} ${name}"
  else
    # 409 when the run finished or is already cancelling: nothing left to save.
    echo "::warning::fail fast: could not cancel run ${id} (${name})"
  fi
}

while read -r id name; do
  [ -n "${id}" ] && cancel "${id}" "${name}"
done <<<"${siblings}"
cancel "${run_id}" "(this run)"
exit 0
