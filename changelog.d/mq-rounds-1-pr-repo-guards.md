### Internal
- **PR CI runs every repo-wide guard.** The `repo-guards` job now runs `scripts/ci/run-guards.sh` on pull requests (merged with main), the same guard set the merge queue runs, and also runs on docs-only PRs. A guard failure now shows on the PR instead of failing a merge-queue round.
