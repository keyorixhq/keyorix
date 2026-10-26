- **INV-STORE-secret-node-cache-epoch-trigger-integrity-checked** On PostgreSQL the periodic
  trigger check (`StartTriggerIntegrityCheck`, role_permission_generation_integrity.go) also
  watches the `secret_nodes` cache-epoch trigger and `keyorix_secret_nodes_bump_cache_epoch()`
  (`secretNodeCacheEpochIntegrityTarget`): ENABLE ALWAYS, BEFORE UPDATE FOR EACH ROW with no
  column list, WHEN clause or arguments (`pgCacheEpochTriggerDefOK`), the function body,
  language and pinned `search_path` of this release (`pgCacheEpochFuncOK` over
  `postgresCacheEpochFuncBody`), and the `pg_trigger`/`pg_proc` row versions against the previous
  reading. On any difference it logs `SECURITY:`, increments
  `keyorix_secret_node_cache_epoch_tamper_total` and moves `cache_epoch` on every live row, which
  makes every replica's warm node entry miss. That bump goes through the trigger being checked, so
  with a bad definition it runs only after the repair, in the repair's transaction (under
  `SET LOCAL lock_timeout`); a repair or bump that fails leaves the checker `pending`. The
  installer (`ensurePostgresCacheEpochTrigger`) rewrites the function only when it differs and
  re-creates a same-named trigger of another shape, so a clean boot of another replica does not
  read as tampering. Both targets also reject a reading taken on a session whose
  `session_replication_role` is not `origin`, as the per-statement proofs do
  (`pgTriggerFiresForEveryWriter`). Why: STARTUP-GUARD-TAILS-1; the cache-epoch trigger had the
  owner-level exposure `docs/design/trigger-rowdigest.md` records: a body that keeps
  `OLD.cache_epoch`, a trigger disabled while a row is changed and re-enabled by the next boot, or
  the DISABLE/write/ENABLE sandwich left warm replicas serving the pre-change row (a suspended
  secret read as active) until the entry's TTL. Residual risk, stated: one interval for deliberate
  DDL; one UPDATE of every live `secret_nodes` row per replica per detection (a false alarm such
  as an older replica's boot during a rolling upgrade costs that too); a superuser below SQL is
  not detected; SQLite is not checked. Guard: (pg-gated)
  `TestSecretNodeCacheEpochIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres`,
  `_ReplaceThenRestoreIsFlushed_Postgres`, `_DisabledTriggerReenabledByBootIsFlushed_Postgres`,
  `_ReplicaTriggerConvergedByBootIsFlushed_Postgres`, `_DroppedFunctionReinstalledByBootIsFlushed_Postgres`,
  `_DroppedFunctionIsRestoredByTheTick_Postgres`, `_DisableWriteEnableInOneTransactionIsFlushed_Postgres`,
  `_TriggerRecreatedAsAfterIsRestored_Postgres`, `_FailedRepairIsRetriedNotAdopted_Postgres`,
  `_CleanTicksAndReplicaBootsDoNotFlush_Postgres`, `_BackgroundJobFlushes_Postgres`;
  `TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres` and
  `_EnsureRestoresRecreatedTrigger_Postgres` (red on the base by behaviour);
  `TestRolePermGenerationIntegrity_NonOriginSessionIsRejected_Postgres` (needs a role that may
  SET `session_replication_role`; skips otherwise).
