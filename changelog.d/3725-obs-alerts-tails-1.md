### Added

- New alert `KeyorixAuditVerifyStateDiscontinuity` (critical) on `keyorix_audit_verify_state_discontinuity`, with a runbook section that points to the audit-chain break runbook. Like the other audit-verification alerts it needs the `keyorix-protected` scrape job.
- `internal/metricsdoc` now checks the alert rule file as text (so it can be tested against a misspelt copy), accepts recording rules defined in the file, requires a severity and a `runbook_url` or `description` on every alert, and pins the owed-audit alert thresholds (1 hour warning, 24 hours critical) from the rule file. The thresholds are unchanged.
