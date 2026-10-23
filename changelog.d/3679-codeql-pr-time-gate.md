### Internal

- CodeQL PR-time gate: on pull_request, `Analyze (server)` now runs for PRs that change non-test Go of the root module (or go.mod/go.sum, the CodeQL query pack, `codeql.yml` or the gate script), analyses without upload and runs the same gate as the merge queue, so a new high-severity finding fails the PR itself instead of a queue group. The merge-queue and PR analyses keep their SARIF as a run artifact (`codeql-sarif-<leg>`, 14 days). A gate-script-only change now runs the gate in the queue too.
