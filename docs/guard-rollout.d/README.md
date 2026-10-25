# docs/guard-rollout.d

One file per repo-wide guard that is still report-only on pull_request and
merge_group runs (docs/guard-rollout-contract.md rule 2). The file is named
`<TestName>.tsv` and holds one tab-separated row:

    test	package	introduced_by	reason

- `test`: the guard's test function; it must report through
  `guardrules.Rollout(t)` (checked by TestGuardRollout_RowsNameAReportingGuard).
- `package`: its directory, relative to the repository root.
- `introduced_by`: the PR that adds or widens the guard, `#NNNN`.
- `reason`: one line.

Lines starting with `#` are comments. On pushes to main and on the nightly
schedule CI sets `KEYORIX_GUARD_ROLLOUT=enforce`, so a listed guard is already
blocking there. Delete the file to make the guard blocking everywhere; the
coordinator's promotion script does that after a green nightly run on main.
