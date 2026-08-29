#!/bin/bash
# detect-mis-based-merges.sh — #1609/G80: base-branch-check (ci.yml) is a
# required status check on main, but it is structurally inert there: it can
# only FAIL when a PR's base isn't main, and required-check enforcement only
# applies where the base branch IS protected -- which today is only main.
# Those two conditions never overlap, so the check cannot block the exact
# mistake it names (a PR merged into a non-main branch -- e.g. a feature
# branch already squash-merged into main separately -- whose content then
# never reaches main on its own: #1563-#1566, #1594). Verified directly:
# PR #1609 was deliberately mis-based and merged with base-branch-check red.
#
# A GitHub ruleset requiring the same check on feat/**/fix/**/adr082/**
# branches was tried and reverted the same day: ruleset required-status-
# checks gate PUSHES to the matching ref, not just merges, and
# base-branch-check only ever runs on pull_request events -- so it can never
# satisfy a push-time requirement for a commit it has not (and will not) run
# against. Every ordinary push creating or updating a matching branch was
# rejected until the ruleset was deleted. There is no ruleset shape found
# that gates the mis-based merge without also gating ordinary feature-branch
# pushes -- prevention is not available with the platform's model here.
#
# This is detection instead: scans PRs merged in the lookback window and
# fails + files an issue for any whose base wasn't main (and isn't in the
# allowlist below). Run on a schedule (mis-based-merge-detector.yml), not as
# a required check -- it cannot block anything, since it doesn't run against
# a PR at all. It must never be added to required checks; that would
# recreate the exact false reassurance base-branch-check already provided
# for weeks before anyone re-derived that it doesn't do what its presence in
# the required list implied.
set -euo pipefail

REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
if [ -z "$REPO" ]; then
    echo "REPO or GITHUB_REPOSITORY must be set" >&2
    exit 2
fi

# LOOKBACK_MINUTES must exceed the schedule interval (hourly) so two
# consecutive runs' windows overlap -- a window equal to the interval drops
# any merge landing in the gap between one run finishing and the next one's
# window starting. 90 minutes against a 60-minute schedule gives a
# 30-minute overlap: a detector with a blind spot is the exact shape this
# campaign keeps finding elsewhere (leg-completeness, exclusion-freshness).
LOOKBACK_MINUTES="${LOOKBACK_MINUTES:-90}"

# legitimate_base_exceptions: same shape and discipline as
# scripts/ci-test-legs.sh's exclusion_entries() -- one entry per line,
# pipe-delimited <base-branch-name>|<reason>|<issue-or-decision-ref>. A PR
# whose base matches an entry here is a deliberate exception, not a
# violation. Empty today: no long-running integration branch or release
# line exists in this repo that a PR legitimately targets instead of main.
# Left as an explicit empty list (a function that produces zero lines), not
# omitted entirely, so the concept has a place to be extended the day a real
# exception exists, rather than being reinvented ad hoc under pressure.
legitimate_base_exceptions() {
    cat <<'EOF'
EOF
}

is_legitimate_exception() {
    local base="$1"
    local entry_base
    while IFS='|' read -r entry_base _reason _ref; do
        [ -z "$entry_base" ] && continue
        [ "$entry_base" = "$base" ] && return 0
    done < <(legitimate_base_exceptions)
    return 1
}

cutoff="$(date -u -d "${LOOKBACK_MINUTES} minutes ago" +%Y-%m-%dT%H:%M:%SZ)"
echo "Scanning PRs merged since ${cutoff} (lookback ${LOOKBACK_MINUTES}m) for a non-main base..."

# is:merged via --state merged, "merged since X" via the search index's
# merged: qualifier -- lets the search API do the date filtering directly
# instead of paging every closed PR and filtering client-side.
prs_json="$(gh pr list --repo "$REPO" --state merged --search "merged:>=${cutoff}" \
    --json number,baseRefName,headRefName,mergedAt,mergeCommit,url,title --limit 100)"

violation_count=0

while IFS= read -r pr; do
    [ -z "$pr" ] && continue
    number=$(jq -r '.number' <<<"$pr")
    base=$(jq -r '.baseRefName' <<<"$pr")
    head=$(jq -r '.headRefName' <<<"$pr")
    merged_at=$(jq -r '.mergedAt' <<<"$pr")
    merge_sha=$(jq -r '.mergeCommit.oid // "unknown"' <<<"$pr")
    pr_url=$(jq -r '.url' <<<"$pr")
    title=$(jq -r '.title' <<<"$pr")

    if [ "$base" = "main" ]; then
        continue
    fi
    if is_legitimate_exception "$base"; then
        echo "ok: PR #${number} based on '${base}' -- allowlisted exception, not a violation"
        continue
    fi

    violation_count=$((violation_count + 1))
    echo "::error::PR #${number} (\"${title}\") merged with base '${base}', not main -- head=${head} merge_commit=${merge_sha} merged_at=${merged_at} ${pr_url}"

    # Idempotence: search ALL issues (open and closed) for a marker tying an
    # existing issue to this exact PR number before filing a new one -- a
    # violation stays inside the overlapping lookback window across
    # multiple runs, so without this every run in that window would file
    # its own duplicate.
    marker="mis-based-merge-detector:pr=${number}"
    existing=$(gh issue list --repo "$REPO" --search "\"${marker}\" in:body" --state all --json number --jq '.[0].number' || true)
    if [ -n "$existing" ]; then
        echo "issue #${existing} already tracks PR #${number} -- not filing a duplicate"
        continue
    fi

    issue_title="Mis-based merge: PR #${number} merged into '${base}', not main"
    issue_body="$(cat <<EOF
Detected by \`scripts/detect-mis-based-merges.sh\` (\`.github/workflows/mis-based-merge-detector.yml\`).

A PR merged with a base branch other than \`main\`. This is the exact shape
that let #1563-#1566 and #1594 show "Merged" on GitHub without their content
ever reaching \`main\` -- if \`${base}\` was already itself merged into
\`main\` (e.g. via squash) before this PR landed on it, this PR's content is
now stranded and will never reach \`main\` on its own.

- PR: #${number} -- ${pr_url}
- Title: ${title}
- Base: \`${base}\` (expected \`main\`)
- Head: \`${head}\`
- Merge commit: \`${merge_sha}\`
- Merged at: ${merged_at}

**Next step:** verify whether this PR's content has actually reached
\`main\` -- \`gh pr view ${number} --json baseRefName\` plus
\`git diff ${head} origin/main --stat\` (empty diff means the content is
already there; see CLAUDE.md's "verify closure by content, not by commit"
practice). If it hasn't, the content needs to land on \`main\` some other
way (a fresh PR, a cherry-pick).

If \`${base}\` is actually a deliberate, standing exception (a long-running
integration branch, a release line), add it to \`legitimate_base_exceptions()\`
in \`scripts/detect-mis-based-merges.sh\` with a reason, rather than closing
this issue and letting the next instance go undetected again.

<!-- ${marker} -->
EOF
)"
    gh issue create --repo "$REPO" --title "$issue_title" --body "$issue_body"
    echo "filed issue for PR #${number}"
done < <(jq -c '.[]' <<<"$prs_json")

if [ "$violation_count" -gt 0 ]; then
    echo "FAIL: ${violation_count} mis-based merge(s) detected in the last ${LOOKBACK_MINUTES} minutes"
    exit 1
fi

echo "ok: no mis-based merges in the last ${LOOKBACK_MINUTES} minutes"
