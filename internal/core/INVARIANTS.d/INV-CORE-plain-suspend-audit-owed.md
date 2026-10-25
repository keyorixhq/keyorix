- **INV-CORE-plain-suspend-audit-owed** A plain suspend (`SuspendSecretWithOptions` without
  `ClearSyncedCopies`, so also every secret of a plain project freeze) is never blocked, delayed or
  failed by the audit log, and its `secret.suspended` row is never silently lost. The status change
  and a `pending_audit_events` record of the owed row commit in ONE transaction
  (`commitOwingAudit`, `audit_owed.go`). If that record cannot be written, the row is named in a
  `SECURITY:` line, the status change is applied on its own (revocation wins) and the record is
  written right after it, before the append wait (RD-TLA-OWED-FIX-1), so a crash at the append
  leaves it pending. A crash loses the row only when no record could be written with or after the
  change: the process dies before that late record commits, the pending table refuses it too and
  the process dies before the direct append, or the event cannot be encoded at all; in the first
  two the earlier `SECURITY:` line names it. The row is then appended and the
  record claimed (`ClaimPendingAuditEvent`, a DELETE reporting whether this call removed it) in one
  transaction, with a bounded wait. A failure is loud: a `SECURITY:` log line with the actor,
  secret and reason, the process counter and the pending count in `GET /api/v1/system/info`
  `security.audit_owed` (system.write only), and the web warning bar. The record stays for
  `BackfillPendingAuditEvents` (scheduler `audit_owed_backfill`), which writes each owed row
  exactly once, whichever writers race: the request, a later pass, or several replicas.
  Why: Andrei 2026-10-14 (revocation is never blocked by audit), SUSPEND-AUDIT-LOUD.
  Guard: `secret_suspend_audit_owed_test.go`
  (`TestSuspendSecret_PlainSuspendAuditIsOwed`: refused audit → suspended, pending, counted, logged;
  backfill once after recovery, chain verifies; lost claim writes nothing; record missing; both
  failing; project freeze); `owed_audit_collect_only_crash_test.go` (record refused once and a crash
  at the append: the row is pending and backfilled after a restart; record always refused: the row
  is named before the change); `secret_suspend_audit_owed_postgres_test.go`
  (`TestSuspendSecret_PlainSuspendAuditOwed_ConcurrentBackfillWritesOnce_Postgres`, pg-gated: 4
  replicas backfill at once, one row per suspension); `server/http/secret_suspend_audit_owed_test.go`
  (`TestSuspendSecret_PlainSuspendAuditOwed_OverTheRouter`).
  Not covered: `secret.bulk_suspend_attempted` (written before a plain freeze) and `secret.resumed`
  stay plain best-effort writes.
