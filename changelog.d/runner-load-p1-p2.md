### Changed
- **CI: less runner contention in the merge queue (MQ-RUNNER-LOAD-1 P1, P2).** The
  nightly and scheduled workflows move out of the 02-05 UTC merge-queue peak to
  06-08 UTC (same order, same off-minute convention). In a merge_group run,
  `preflight` and `lint` are skipped when the group commit has the byte-identical
  git tree that a passing `pull_request` run of the PR head already tested; any
  other case, including a lookup error, runs them as before. Job names and the
  required checks are unchanged.
