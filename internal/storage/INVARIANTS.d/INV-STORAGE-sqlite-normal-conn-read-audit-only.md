- **INV-STORAGE-sqlite-normal-conn-read-audit-only** On SQLite, the only transaction that may
  commit on a connection with `PRAGMA synchronous` below FULL is an audit-flusher batch whose
  EVERY row is a successful secret-value read audit (`secret.read`, `connect.secret_read`,
  `Success=true`), and only at `storage.database.audit_durability: standard`; that connection is
  a separate one-connection handle to the same database file whose pragma is fixed in its DSN.
  Every mutation, every mutation's audit row, denied reads, mixed batches and appends inside a
  caller's transaction commit on the shared FULL pool. Why: ADR-112 Amendment 7. A NORMAL commit
  is lost to an OS crash or power loss until the next WAL sync; for read audits that is a tail
  of the chain (both handles append to one `-wal` file under one write lock, so a later FULL
  commit makes every earlier row durable), for a mutation it would undo a committed revocation
  or rotation. Guard: `internal/storage` `TestSQLiteReadAuditConn_OnlyReadBatchesUseNormal` and
  `TestSQLiteReadAuditConn_PragmaPerConnection` (PRAGMA synchronous read inside the committing
  transaction), `TestSQLiteReadAuditConn_InterleavedChainVerifies` (both handles, chain valid);
  `internal/storage/store` `TestSQLiteReadAuditDB_UsedOnlyByTheAuditBatchSelector` (go/parser:
  the NORMAL handle is used only by its setter, `Close` and `auditBatchDB`; calibrated red with a
  probe file) and `TestIsSQLiteNormalReadAuditBatch`; `internal/core`
  `TestSQLiteNormalReadAuditEventTypes_MatchCore` (the event set equals Amendment 4's
  value-read set). **Not covered**: OS-crash and power-loss behaviour (rests on SQLite's WAL
  design; pending e2e VM, dm-flakey), a second process opening the file with its own pragmas
  (the CLI admin commands use `sqliteDSN`, FULL), reflect/unsafe access to the field.
