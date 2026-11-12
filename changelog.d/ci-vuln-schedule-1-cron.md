### Internal
- **Scheduled govulncheck now runs every 3 hours** (was weekly), so a newly published reachable Go vulnerability is flagged within hours instead of at the next incidental PR (GO-2026-6859 went unnoticed for ~10 h). `scripts/ci/failure-issue.sh` gained an opt-in `FAILURE_ISSUE_MIN_COMMENT_HOURS` so repeated reds comment on the one open alert issue at most once per day.
