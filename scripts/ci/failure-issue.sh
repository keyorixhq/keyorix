#!/usr/bin/env bash
# failure-issue.sh -- one GitHub issue per scheduled job, not one per failure.
#
# Usage: scripts/ci/failure-issue.sh <failure|success> "<issue title>" ["<detail>"]
#   failure: open the issue if none is open with this exact title, otherwise
#            add a comment with this run's link. Optional third arg is extra
#            body text (e.g. the specific failing steps) appended after the
#            run link, on both the create and the comment path.
#   success: close the open issue with this exact title (if any), with a
#            comment linking the green run. Third arg is ignored.
#
# Optional env FAILURE_ISSUE_MIN_COMMENT_HOURS=N: on a repeat failure, comment
# only if the issue was created or last commented on at least N hours ago (for
# schedules that run many times a day). Default 0 = comment every time.
#
# Needs GH_TOKEN with issues: write, plus GITHUB_REPOSITORY, GITHUB_SERVER_URL
# and GITHUB_RUN_ID (all set by Actions). No external service and no secrets:
# GitHub's own notifications (email / mobile push) deliver the alert.
set -euo pipefail

outcome="${1:?usage: failure-issue.sh <failure|success> <title> [detail]}"
title="${2:?usage: failure-issue.sh <failure|success> <title> [detail]}"
detail="${3:-}"
label="ci-scheduled-failure"
repo="${GITHUB_REPOSITORY:?}"
run_url="${GITHUB_SERVER_URL:?}/${repo}/actions/runs/${GITHUB_RUN_ID:?}"

case "$outcome" in
failure | success) ;;
*)
	echo "failure-issue.sh: outcome must be failure or success, got '$outcome'" >&2
	exit 2
	;;
esac

# Exact-title match among open issues carrying our label (GitHub search is
# fuzzy, so filter the exact title here).
existing=$(gh issue list --repo "$repo" --state open --label "$label" --limit 100 \
	--json number,title |
	jq -r --arg t "$title" '[.[] | select(.title == $t) | .number][0] // empty')

if [ "$outcome" = "failure" ]; then
	detail_block=""
	[ -n "$detail" ] && detail_block="

${detail}"
	if [ -n "$existing" ]; then
		# Optional throttle for frequent schedules (govulncheck-scheduled runs
		# every 3 h): skip the comment when the issue was created or last
		# commented on less than FAILURE_ISSUE_MIN_COMMENT_HOURS ago. Unset or
		# 0 keeps the old behaviour (comment on every failure).
		min_hours="${FAILURE_ISSUE_MIN_COMMENT_HOURS:-0}"
		if [ "$min_hours" != "0" ]; then
			age_s=$(gh issue view "$existing" --repo "$repo" --json createdAt,comments |
				jq -r '([.createdAt] + [.comments[].createdAt] | max | fromdateiso8601) as $t | (now - $t) | floor')
			if [ "$age_s" -lt $((min_hours * 3600)) ]; then
				echo "#${existing} touched ${age_s}s ago (< ${min_hours}h); not commenting again"
				exit 0
			fi
		fi
		gh issue comment "$existing" --repo "$repo" --body "Failed again: ${run_url}${detail_block}"
		echo "commented on #${existing}"
	else
		# Idempotent: fails harmlessly if the label already exists.
		gh label create "$label" --repo "$repo" --color B60205 \
			--description "Opened automatically when a scheduled CI job fails; closed on its next green run" \
			>/dev/null 2>&1 || true
		gh issue create --repo "$repo" --label "$label" --title "$title" \
			--body "A scheduled CI job failed: ${run_url}${detail_block}

This issue is managed by \`scripts/ci/failure-issue.sh\`: later failures add a comment here, and the next green run closes it."
	fi
else
	if [ -n "$existing" ]; then
		gh issue close "$existing" --repo "$repo" --comment "Green again: ${run_url}"
		echo "closed #${existing}"
	else
		echo "no open issue titled '${title}'; nothing to do"
	fi
fi
