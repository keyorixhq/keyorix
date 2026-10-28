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
  it runs only after the repair, which commits in its own transaction first (under
  `SET LOCAL lock_timeout`): a row lock the bump waits on never rolls the repair back. The bump
  runs in committed batches of `secretNodeCacheEpochInvalidateBatch` rows by id that continue
  across ticks, and the checker stays `pending` until the last batch and after a failed repair. A
  reading the repair cannot fix (a session not in `origin`) is reported every tick and bumped once
  per reading (`checkRepairFirst`). The
  installer (`ensurePostgresCacheEpochTrigger`) rewrites the function only when it differs and
  re-creates a same-named trigger of another shape, so a clean boot of another replica does not
  read as tampering. Both targets also reject a reading taken on a session whose
  `session_replication_role` is not `origin`, as the per-statement proofs do
  (`pgTriggerFiresForEveryWriter`). Why: STARTUP-GUARD-TAILS-1; the cache-epoch trigger had the
  owner-level exposure `docs/design/trigger-rowdigest.md` records: a body that keeps
  `OLD.cache_epoch`, a trigger disabled while a row is changed and re-enabled by the next boot, or
  the DISABLE/write/ENABLE sandwich left warm replicas serving the pre-change row (a suspended
  secret read as active) until the entry's TTL. Residual risk, stated: one interval for deliberate
  DDL, longer while the batched bump of a large table spans ticks; every replica that sees a
  change rewrites every live `secret_nodes` row once, so a false alarm (such as an older
  release's replica rewriting the function at boot during a rolling upgrade) costs a full-table
  write and refill per replica, not one cache refill; only the checked trigger and its function
  are read, so a second BEFORE UPDATE trigger on `secret_nodes` that fires later by name (e.g.
  `zz_…`) and sets `NEW.cache_epoch := OLD.cache_epoch`, or a rule on `secret_nodes`, is not
  detected (in single_writer mode the solewriter census fingerprints every `pg_trigger`/
  `pg_rewrite` row on fenced tables, `secret_nodes` included, and catches it; in the default mode
  nothing does); a superuser below SQL is not detected; SQLite is not checked. Guard: (pg-gated)
  `TestSecretNodeCacheEpochIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres`,
  `_ReplaceThenRestoreIsFlushed_Postgres`, `_DisabledTriggerReenabledByBootIsFlushed_Postgres`,
  `_ReplicaTriggerConvergedByBootIsFlushed_Postgres`, `_DroppedFunctionReinstalledByBootIsFlushed_Postgres`,
  `_DroppedFunctionIsRestoredByTheTick_Postgres`, `_DisableWriteEnableInOneTransactionIsFlushed_Postgres`,
  `_TriggerRecreatedAsAfterIsRestored_Postgres`, `_FailedRepairIsRetriedNotAdopted_Postgres`,
  `_CleanTicksAndReplicaBootsDoNotFlush_Postgres`, `_BackgroundJobFlushes_Postgres`,
  `_RepairCommitsWhenTheInvalidationCannotLockARow_Postgres`,
  `_InvalidationResumesAcrossTicks_Postgres`;
  `TestSecretNodeCacheEpoch_EnsureLeavesCorrectFunctionRowAlone_Postgres` and
  `_EnsureRestoresRecreatedTrigger_Postgres` (red on the base by behaviour);
  `TestRolePermGenerationIntegrity_NonOriginSessionIsRejected_Postgres` and
  `TestSecretNodeCacheEpochIntegrity_NonOriginSessionInvalidatesOncePerReading_Postgres` (need a
  role that may SET `session_replication_role`; skip otherwise).
