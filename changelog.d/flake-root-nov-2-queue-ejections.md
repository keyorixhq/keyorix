### Testing
- **A fixed known finding no longer ejects an unrelated PR from the merge queue.** New
  `guardrules.KnownFindingClosed`: the four tests that pin "bug X still exists" (backend
  differential A, `knownWipeGaps`, `machineGranterTagExempt`, `knownUnauditedOperations`)
  log `FINDING CLOSED` on pull_request and merge-queue runs and fail only under
  `KEYORIX_GUARD_ROLLOUT=enforce` (main push, nightly). Behaviour while the bug is present
  is unchanged.
- The invariants-index guard now quotes the duplicate or second **Total** row and the
  column sums to keep; the edge unattended tests print the server log tail with an
  unexpected status.
