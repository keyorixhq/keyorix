### Testing

- `docs/INVARIANTS.md` no longer carries a hand-kept Total row; `TestInvariantsIndexHasNoDuplicateRowsAndTotalsAddUp` computes and logs the sums, so two PRs editing the counts table cannot fail each other in the merge queue (#4237).
- `TestKnownOpenTolerances_AreLoadBearing` reports a dead tolerance through `guardrules.KnownFindingClosed`: logged on pull_request/merge_group runs, failing on main and the nightly run.
