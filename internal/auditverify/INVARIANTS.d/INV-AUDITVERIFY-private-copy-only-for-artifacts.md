- **INV-AUDITVERIFY-private-copy-only-for-artifacts** Only an operator-named SQLite artifact
  (`verify-audit --db`, `OpenSQLiteReadOnly`) is verified from a private copy under `$TMPDIR`,
  and that copy is removed on Close, on error, and on SIGINT/SIGTERM (`RemovePrivateCopy`
  from `removeCopyOnSignal`). A server-owned database (the config fallback under the admin
  lock, the database `admin restore` just wrote) is opened in place
  (`OpenSQLiteReadOnlyInPlace`) and never copied. A `-wal` beside the artifact that is not a
  regular file is an open error, never left out of the copy. Why: the copy is the whole vault
  database (ciphertext, hashes, PII); REVIEW-4553-DEEP-1 found it made on every restore and
  config-fallback run and left behind on interrupt. Guard: server/admin
  `TestVerifyRestoredAudit_WALDatabaseNeedsNoTempDir`,
  `TestVerifyAudit_ConfigFallbackWALDatabaseNeedsNoTempDir`,
  `TestVerifyAudit_DBCopyRemovedOnSIGINT`; `TestOpenSQLiteReadOnly_NonRegularWALRefused`,
  `TestRemovePrivateCopy_BeforeCloseRemovesCopy`. Not covered: SIGKILL, an OOM kill or a
  crash leaves the `keyorix-audit-verify-*` directory (documented in the runbook).
