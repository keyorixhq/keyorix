- **INV-CORE-dynamic-issue-reports-account-before-write** A dynamic-secret engine that
  creates an account on the target (postgres, mysql, mongodb, redis) names it through
  `ports.ReportIssuedRole(ctx, name)` once the name is generated and before the first
  statement that can create it, and `IssueLease` hands it a context carrying the reporter
  (`ports.WithIssuedRoleReporter`). When `Issue` then fails (a contained client panic after
  the target created the account is the case that matters), core cannot know whether the
  account exists, so it revokes it by name (`cleanupAbortedIssue`, every database engine's
  `Revoke` is idempotent); a revoke that fails leaves a `revoke_failed` lease row naming the
  account, plus the `dynamic_lease.revoke_failed` audit event, which the sweep and the
  manual retry both pick up. The cleanup runs on a context detached from the request's
  cancellation (a timeout is one reason `Issue` fails). An engine that never reports (the
  cloud engines create no account) gets no cleanup call. Why: `Issue` returns the account
  name only on success, so a panic after `CREATE ROLE` left a live database account that no
  lease row, sweep or revoke could reach.
  Guard: `internal/core/dynamic_secrets_issue_abort_test.go`
  (`TestDynamicSecrets_IssuePanicAfterCreateIsRecordedAndSwept`,
  `...RevokesImmediately`, `...WithoutReportRevokesNothing`) and
  `internal/dynamic/issue_report_test.go` (the MySQL engine reports before the first write
  and the reported name is the one in `CREATE USER`).
  **Not covered**: postgres, mongodb and redis `Issue` are not driven against a fake target
  that panics after the create (only MySQL has the recording driver), so the position of
  their `ReportIssuedRole` call is checked by review; the report is held in memory, so a
  process crash between the target write and the cleanup still orphans the account (the
  pre-existing `IssueLease` crash-orphan note, #97).
