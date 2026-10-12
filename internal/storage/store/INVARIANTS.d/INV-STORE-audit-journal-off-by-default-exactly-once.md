- **INV-STORE-audit-journal-off-by-default-exactly-once** The ADR-115 local audit journal
  (experimental) changes nothing unless enabled: `localAuditJournal` is nil on every
  LocalStorage unless `EnableLocalAuditJournal` ran on that exact root store (never on a
  transaction-scoped clone), so `logAuditEvent` takes main's flusher/direct path, and no
  journal state lives on `audit_events` (origin is in `audit_journal_origins`). When enabled,
  a journal record reaches `audit_events` exactly once: the replay cursor commits in the same
  transaction as the rows, is re-read inside that transaction after the audit lock so a
  retried batch is a no-op, and `audit_journal_origins`' (replica_id, seq) primary key rejects
  a duplicate. A closed journal fails audit writes with `auditjournal.ErrClosed`; it never
  falls back to the DB path. Startup refuses a journal shorter than the DB replay cursor.
  Guard: `internal/storage` `TestLocalAuditJournal_OffByDefault`,
  `TestLocalAuditJournal_RefusesIncompleteOrConflictingConfig`; `internal/storage/store`
  `TestReplayJournalRecords_RetryOfCommittedBatchIsNoOp`, `TestAuditJournalOrigin_ReplicaSeqIsUnique`,
  `TestEnableLocalAuditJournal_RefusesJournalShorterThanCursor`,
  `TestCloseLocalAuditJournal_WithWritersInFlight`, `TestLocalAuditJournal_KillNineLoop`,
  `TestLocalAuditJournal_Postgres_ReplayAndRestart` (pg-gated).
