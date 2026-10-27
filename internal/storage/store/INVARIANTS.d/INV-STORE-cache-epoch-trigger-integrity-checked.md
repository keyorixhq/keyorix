- **INV-STORE-cache-epoch-trigger-integrity-checked** On PostgreSQL the job started by
  `StartRolePermissionsGenerationIntegrityCheck` (every factory-built store; one ticker, one
  `Close` path) also runs `secretNodeCacheEpochIntegrityChecker` every
  `rolePermGenerationIntegrityInterval` and once at start. One catalog statement reads
  `trg_secret_nodes_cache_epoch` and its function: the trigger must be BEFORE UPDATE FOR EACH ROW
  with no column list, WHEN clause or arguments, ENABLE ALWAYS, and call
  `keyorix_secret_nodes_bump_cache_epoch()` (`pgSecretNodeCacheEpochTriggerDefOK`); the function
  must have exactly `postgresSecretNodeCacheEpochFuncBody` as `prosrc` (the text itself, not a
  hash of it), be plpgsql, have `proconfig` exactly the pinned search_path
  (`pgTriggerFuncConfigOK`) and not be SECURITY DEFINER (`pgSecretNodeCacheEpochFuncOK`). It also
  compares the `tgfoid`/`xmin` row versions with the previous reading, so a change undone before
  the next tick still shows. On any difference it logs a `SECURITY:` line, increments
  `keyorix_secret_node_cache_epoch_tamper_total`, bumps `cache_epoch` of every `secret_nodes` row in
  a transaction of its own (every replica's node cache re-reads), re-installs under
  `SET LOCAL lock_timeout` (`ensurePostgresCacheEpochTrigger`) and bumps again. A failed bump or
  repair keeps the checker `pending`: every tick bumps and retries until a repair commits and the
  re-read is clean, and the current catalog is never adopted as a new baseline meanwhile. The
  installer replaces the function only when it is missing or differs and re-creates a same-named
  trigger whose definition differs, so a clean boot of another replica moves no row version and
  raises no alarm. Why: TRIGGER-HARDEN-1, the follow-up of TRIGGER-ROWDIGEST-1
  (`docs/design/trigger-rowdigest.md`): the function owner (the server's own role, no superuser
  needed) could replace the body, or re-create the trigger as AFTER or with a WHEN clause, while the
  per-read proof still passed, and a direct update then left the stamp unchanged and warm replicas
  served the old row. Residual risk, stated: one interval for deliberate DDL; a superuser acting
  below SQL is not detected; the `cache_epoch` column itself is not covered (another BEFORE UPDATE
  trigger that overwrites it, a revoked column privilege, a rule); a table-wide bump costs one
  UPDATE of `secret_nodes` per detected change and per tick while a repair keeps failing; SQLite is
  not checked. Guard: (pg-gated) `secret_node_cache_epoch_integrity_postgres_test.go`
  (`TestSecretNodeCacheEpochIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres`,
  `_AlteredSearchPathIsRestored_Postgres`, `_SecurityDefinerIsRestored_Postgres`,
  `_DisableWriteEnableInOneTransactionIsFlushed_Postgres`, `_ReplaceThenRestoreIsFlushed_Postgres`,
  `_TriggerRecreatedAfterOrWithWhenIsRestored_Postgres`, `_FailedRepairIsRetriedNotAdopted_Postgres`,
  `_BackgroundJobFlushesAndStopsOnClose_Postgres`; the other direction:
  `_CleanTicksAndReplicaBootsDoNotFlush_Postgres`) and
  `secret_node_cache_epoch_ensure_postgres_test.go`
  (`TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres`,
  `_EnsureRestoresRecreatedTrigger_Postgres`; both red on the base by behaviour).
