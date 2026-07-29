#!/usr/bin/env bash
# On a fuzz crash, opens (or comments on) a GitHub PR from the fuzz-corpus
# branch so the reproducer lands in main as a permanent regression test, and
# optionally sends an ntfy.sh push notification for real-time alerting.
#
# Deduped per unique failure: a target that re-fails on the same crasher
# every rotation does not open duplicate PRs or re-alert every cycle.
set -euo pipefail

FUNC="${1:?fuzz func name}"
PKG="${2:?package path}"
LOGFILE="${3:?path to the log file for this run}"

: "${NOTIFIED_STATE_DIR:?}"
: "${KEYORIX_REPO:?}"
: "${FUZZ_CORPUS_BRANCH:=fuzz-corpus}"

fail_line="$(grep -m1 -E 'FAIL|panic:' "$LOGFILE" || true)"
fail_hash="$(printf '%s' "${fail_line:-unknown}" | sha256sum | cut -c1-16)"
marker="$NOTIFIED_STATE_DIR/notified-$FUNC-$fail_hash"

if [[ -f "$marker" ]]; then
  exit 0 # already alerted for this exact failure
fi

summary="$(grep -m8 -E 'FAIL|panic:|--- FAIL|Fatalf|\.go:[0-9]+' "$LOGFILE" | head -c 1500 || true)"

# ntfy.sh push notification (optional — skip if NTFY_TOPIC is unset or empty)
if [[ -n "${NTFY_TOPIC:-}" ]]; then
  curl -fsS \
    -H "Title: keyorix fuzz: $FUNC crashed" \
    -H "Priority: high" \
    -H "Tags: rotating_light" \
    -d "$PKG :: $FUNC

${summary:-see log on the fuzz box}

Reproducer pushed to the $FUZZ_CORPUS_BRANCH branch." \
    "$NTFY_TOPIC" >/dev/null || true
fi

# GitHub PR — open from fuzz-corpus to main, or comment on the existing one.
# Authenticated via GH_TOKEN in /etc/keyorix-fuzz/config.env (see README.md
# step 3). Required PAT scopes: Contents (Read), Pull requests (Read+Write).
reproduce_cmd="go test -run=^${FUNC}\$ -fuzz=^${FUNC}\$ ./${PKG}"
pr_body="## Fuzz crash: \`$FUNC\`

**Package:** \`$PKG\`

**Reproduce:**
\`\`\`
$reproduce_cmd
\`\`\`

**Failure (truncated):**
\`\`\`
${summary:-see log on the fuzz box}
\`\`\`

The crashing input is committed to the \`$FUZZ_CORPUS_BRANCH\` branch and will be in \`testdata/fuzz/$FUNC/\` once this PR merges. Fix the bug, add it to the relevant test, then merge this PR to lock the regression test in."

# Log gh errors to a persistent file so auth/permission failures are visible.
# Do NOT use 2>/dev/null — silent failures caused markers to be written for
# crashes that were never actually reported, permanently suppressing them.
gh_err="$NOTIFIED_STATE_DIR/gh-error-$FUNC-$fail_hash.log"

cd "$KEYORIX_REPO"
pr_notified=false
existing_pr="$(gh pr list --head "$FUZZ_CORPUS_BRANCH" --state open --json number --jq '.[0].number' 2>>"$gh_err" || true)"
if [[ -n "$existing_pr" ]]; then
  if gh pr comment "$existing_pr" \
    --body "**Additional crash ($(date -u +%FT%TZ)):** \`$FUNC\` — hash \`$fail_hash\`
\`\`\`
$fail_line
\`\`\`" 2>>"$gh_err"; then
    pr_notified=true
  fi
else
  if gh pr create \
    --title "fuzz(crash): $FUNC — crash reproducer" \
    --body "$pr_body" \
    --head "$FUZZ_CORPUS_BRANCH" \
    --base main 2>>"$gh_err"; then
    pr_notified=true
  fi
fi

# Only mark as notified when gh actually succeeded. If not, emit a visible
# error so the systemd journal (journalctl -u keyorix-fuzz.service) shows it,
# and leave the marker unwritten so the next rotation retries.
if $pr_notified; then
  touch "$marker"
else
  echo "notify-on-crash: GitHub notification failed for $FUNC (hash $fail_hash) — see $gh_err" >&2
fi
