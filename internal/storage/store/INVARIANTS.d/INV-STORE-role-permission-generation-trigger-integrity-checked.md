- **INV-STORE-role-permission-generation-trigger-integrity-checked** On PostgreSQL every
  factory-built store runs `StartRolePermissionsGenerationIntegrityCheck`. Every
  `rolePermGenerationIntegrityInterval` (and once at start) it reads both generation triggers
  and their function in one catalog statement. It checks the definition against this release
  (`pgRolePermGenerationTriggerDefOK`, `pgRolePermGenerationFuncOK` over
  `postgresRolePermGenerationFuncBody`; ENABLE ALWAYS; one shared function) and compares the
  `pg_trigger`/`pg_proc` row versions (`tgfoid`, `xmin`) with the previous reading. On any
  difference it logs a `SECURITY:` line, increments `keyorix_role_permission_generation_tamper_total`,
  re-installs the triggers if the definition is wrong, and bumps `role_permissions_generation` in
  the same transaction, so every replica's cache refills from the live join. The installer
  re-creates a same-named trigger whose definition differs, and never rewrites a function row
  that is already correct: a clean boot of another replica must not read as tampering.
  `postgresRolePermGenerationFuncBody` is the one source of the function body. A release that
  changes it must also let the check accept the previous body during a rolling upgrade, or older
  replicas' boots read as tampering on newer ones (a cache flush each time, not a wrong decision).
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
  `_CleanTicksAndReplicaBootsDoNotFlush_Postgres`, `_BackgroundJobFlushesAndStopsOnClose_Postgres`;
  `TestRolePermissionGeneration_EnsureLeavesCorrectFunctionRowAlone_Postgres`,
  `_EnsureRestoresRecreatedTrigger_Postgres` (both red on the base by behaviour).
