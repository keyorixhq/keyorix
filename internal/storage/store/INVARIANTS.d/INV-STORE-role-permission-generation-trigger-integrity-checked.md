- **INV-STORE-role-permission-generation-trigger-integrity-checked** On PostgreSQL every
  factory-built store runs `StartTriggerIntegrityCheck`. Every
  `rolePermGenerationIntegrityInterval` (and once at start) it reads both generation triggers
  and their function in one catalog statement. It checks the definition against this release
  (`pgRolePermGenerationTriggerDefOK`, `pgRolePermGenerationFuncOK` over
  `postgresRolePermGenerationFuncBody`; ENABLE ALWAYS; one shared function) and compares the
  `pg_trigger`/`pg_proc` row versions (`tgfoid`, `xmin`) with the previous reading. On any
  difference it logs a `SECURITY:` line, increments `keyorix_role_permission_generation_tamper_total`,
  bumps `role_permissions_generation` in a transaction of its own (so every replica's cache
  refills from the live join even when the repair cannot finish), then, if the definition is
  wrong, re-installs the triggers under `SET LOCAL lock_timeout`
  (`rolePermGenerationRepairLockTimeout`) and bumps again in that transaction. Each background
  tick has a deadline (`rolePermGenerationIntegrityTickTimeout`). A failed repair or bump never
  resets the baseline: the checker stays `pending`, and every tick bumps and retries the repair
  until a repair commits and the re-read is clean (a body restored after a failed repair must
  still flush). Both trigger functions (this one and `keyorix_secret_nodes_bump_cache_epoch()`) pin
  `search_path = pg_catalog, pg_temp` (`pgTriggerFuncSetClause`), and the check accepts exactly
  that `proconfig`, so a writer's search_path cannot shadow the operators the bodies use. The installer
  re-creates a same-named trigger whose definition differs, and never rewrites a function row
  that is already correct: a clean boot of another replica must not read as tampering.
  `postgresRolePermGenerationFuncBody` is the one source of the function body. A release that
  changes it, the settings or the trigger shape bumps `rolePermGenerationDef.version`, so that
  older replicas leave its definition in place during a rolling upgrade
  (INV-STORE-trigger-definition-version-marker). The release that added this check was such a
  change before markers existed: older replicas re-create the function
  without the `SET` clause on every boot, so during that rollout each of their boots raises the
  `SECURITY:` line, the tamper counter, a repair and a fleet-wide flush on the new replicas.
  This complements INV-STORE-role-permission-generation-trigger-maintained, whose per-statement
  proof keeps the zero window for missing or disabled triggers. Why: TRIGGER-ROWDIGEST-1
  (`docs/design/trigger-rowdigest.md`). The function owner (the server's own role, no superuser
  needed) could replace the body or re-create a trigger on fewer events while the proof still
  passed, and a direct-SQL revocation kept authorizing from warm caches until restart. Residual
  risk, stated: one interval for deliberate DDL; a superuser acting below SQL is not detected;
  SQLite is not checked. Guard: (pg-gated)
  `TestRolePermGenerationIntegrity_ReplacedBodyIsRestoredAndFlushed_Postgres`,
  `_DisableWriteEnableInOneTransactionIsFlushed_Postgres`, `_ReplaceThenRestoreIsFlushed_Postgres`,
  `_TriggerRecreatedOnFewerEventsIsRestored_Postgres`, `_FunctionSettingsAreRestored_Postgres`,
  `_CleanTicksAndReplicaBootsDoNotFlush_Postgres`, `_BackgroundJobFlushesAndStopsOnClose_Postgres`,
  `_FailedRepairIsRetriedNotAdopted_Postgres`, `_BlockedRepairStillFlushes_Postgres`; `TestRolePermGeneration_FunctionPinsSearchPath_Postgres`,
  `TestRolePermGeneration_WriterSearchPathCannotShadowTheBump_Postgres`,
  `TestSecretNodeCacheEpoch_FunctionPinsSearchPath_Postgres`,
  `TestSecretNodeCacheEpoch_WriterSearchPathCannotShadowTheBump_Postgres` (all red on the PR base);
  `TestRolePermissionGeneration_EnsureLeavesCorrectFunctionRowAlone_Postgres`,
  `_EnsureRestoresRecreatedTrigger_Postgres` (both red on the base by behaviour).
