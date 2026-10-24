- **INV-CORE-owed-audit-age-metric** `keyorix_audit_owed_oldest_pending_age_seconds` is the age
  (per the core clock) of the oldest `pending_audit_events` row, 0 when none is pending, so an owed
  audit row that is delayed cannot become one that never arrives unseen: the count
  (`keyorix_audit_owed_pending`) cannot tell the two apart, the age can
  (`KeyorixAuditOwedOldestPendingWarn` / `...Critical`, `deploy/observability/prometheus-alerts.yaml`).
  Its read (`OldestPendingAuditEventAt`) is a plain `ORDER BY created_at LIMIT 1` on
  `idx_pending_audit_events_created_at`: an index walk on SQLite and PostgreSQL, never a table scan or
  sort, and no row lock (no `FOR UPDATE`), so it neither waits for nor blocks the backfill's claim. It
  is bounded by `owedAuditScrapeTimeout`. A read that fails or times out makes BOTH owed-audit gauges
  answer NaN (never 0, never the last value) and increments
  `keyorix_audit_owed_metric_scrape_errors_total`, which `KeyorixAuditOwedMetricUnreadable` alerts on:
  the audit outage itself cannot hide the queue behind a zero. An age below zero (another replica's
  clock ahead) reads 0.
  Why: Andrei 2026-10-20 (AUDIT-OWED-AGE-ALERT-1); #3477 exposed only the count.
  Guard: `internal/core` `TestOwedAuditOldestPendingAge_SQLite` and `_Postgres` (the same scenario:
  unknown without a source, empty = 0, oldest row wins, follows a controlled clock, drops to the next
  row when the oldest is claimed, future-dated row = 0),
  `TestOwedAuditOldestPendingAge_SQLitePlanUsesTheCreatedAtIndex` and
  `_PostgresPlanUsesTheCreatedAtIndex` (EXPLAIN of the exact query the code ran: the index, no sort),
  `_PostgresScrapeDoesNotWaitOnBackfillLocks` (an uncommitted claim DELETE does not block or hide the
  row), `_UnreadableIsNaNAndCounted` and `_HungStoreIsBoundedAndCounted` (NaN, counter, bounded
  wait); `internal/metricsdoc` `TestAlertRules_StructureMetricsAndRunbooks` (the alerts use only metrics
  that exist and each has a runbook section) and the metrics reference check.
  Not covered: that the PromQL thresholds fire as the descriptions say (promtool is not in CI); a
  `pending_audit_events` row with a NULL `created_at` (none is written by this code) is counted by
  the count gauge but not seen by the age.
