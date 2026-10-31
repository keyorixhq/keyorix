- **INV-STORE-system-metadata-write-target-checked** The role-permission generation target's
  catalog statement also reads `system_metadata`, the table the generation triggers, the in-app
  bump and the check's own invalidation `UPDATE` (`systemMetadataWriteTargetSQL`). It must be a
  plain table without inheritance children, with no non-internal trigger except the
  retention-anchor trigger exactly as `EnsureAuditRetentionAnchorTrigger` creates it
  (`systemMetadataAnchorTriggerOK`: BEFORE UPDATE FOR EACH ROW, its function, and its
  `WHEN (key = 'audit_retention_anchor')` clause, read from `pg_get_triggerdef`, never
  `pg_get_expr`, which raises an error for a clause referencing `NEW`) and, only in single_writer mode
  (`LocalStorage.SetSingleWriter` from `storage.database.single_writer`, so
  `rolePermGenerationSingleWriterIntegrityTarget`), the fence's AFTER triggers
  (`systemMetadataFenceTriggerOK`: `SoleWriterFenceTriggerPrefix`, executing
  `SoleWriterGuardFunc` with exactly `SoleWriterGuardFuncBody`, a copy of `internal/solewriter`'s
  that `TestFenceGuard_MatchesTheStore` keeps in step). What the guard calls and its settings are
  checked by the fence's own census, which runs only in that mode; outside it a fence-named trigger
  is foreign (PR #3841 review F1: a planted callee pinned the generation row back). It must have
  no rule, and `relrowsecurity` and `relforcerowsecurity` must be false. The xmin of its `pg_class` row and of each trigger and rule row is
  part of the fingerprint. On a violation the check logs `SECURITY:`, counts `reason="tamper"`, and
  the repair (`restoreSystemMetadataWriteTarget`, in the repair transaction under its
  `lock_timeout`) drops the foreign triggers and rules, re-creates the anchor trigger if it dropped
  it, turns row level security off, and bumps the generation. A failed first invalidation (a rule
  makes PostgreSQL refuse every bump's `INSERT ... ON CONFLICT`) does not stop the repair. A
  reading that fails fails closed (`readFailed`): every failed tick invalidates, and from
  `triggerIntegrityReadFailureLimit` failures in a row on it is logged `SECURITY:`, counted
  `reason="tamper"` once per run, and an invalidation is owed until a reading verifies (PR #3841
  review N1: an anchor-named trigger whose WHEN clause referenced `NEW` failed every reading, so
  nothing was flushed, reported or repaired). A reading that runs out of the tick's time is a
  failed reading too; only a cancelled tick (shutdown) changes nothing, and the reading gets half of
  the tick's remaining time so the invalidation keeps the rest (PR #3841 review B1 of bc3739478: the
  server's role can make the reading slow with a huge WHEN clause on the anchor-named trigger, and
  every tick that hit its deadline changed nothing). The reading, the installers' reading, the write-target
  repair's reads and the installers' definition reads run under `readCatalog`: search_path
  `pg_catalog, pg_temp`, with the server's schema bound and every table named through
  `catalogRelSQL`, so no operator, function or type outside pg_catalog takes part and the deparsed
  clause names pg_catalog's `=` only when it is pg_catalog's. Search_path order alone is no defence
  for a read: an operator whose argument types match exactly is picked before one reached by a
  coercion, wherever it sits (PR #3841 fourth review C1: an `=` on (oid, regclass) the role created
  in its own schema pointed `'system_metadata'::regclass` at a decoy table, with the default
  search_path). The repair's DDL runs with pg_catalog searched first (`pinCatalogSearchPathSQL`), so
  the anchor trigger it re-creates calls pg_catalog's `=` on (text, text) (PR #3841 review B2: an
  `=` the role created in its own schema, under a role-level search_path listing that schema first,
  deparsed as installed while it let the generation row through). Why:
  #3713. A `BEFORE UPDATE` trigger keeping `OLD.value`, a rule, or forced row level security with
  an `UPDATE` policy hiding the generation row made every bump a no-op, including the check's own,
  while every trigger and function the check compared read as correct; the permission cache has no
  TTL, so a direct-SQL revocation kept authorizing from warm caches. Residual risk, stated: a
  `system_metadata` that is not a plain table is reported every tick but not repaired; a release
  that needs its own trigger, rule or policy on `system_metadata` must first ship a check that
  allows it; a superuser below SQL is not detected; SQLite is not checked. Guard: (pg-gated)
  `TestRolePermGenerationIntegrity_SystemMetadataBeforeUpdateTriggerIsRemovedAndFlushed_Postgres`,
  `_SystemMetadataRuleIsRemovedAndFlushed_Postgres`,
  `_SystemMetadataForcedRowSecurityIsTurnedOffAndFlushed_Postgres`,
  `_SystemMetadataAnchorTriggerWithoutItsWhenIsRestored_Postgres` (all red on the base by
  behaviour), `_SystemMetadataAnchorTriggerWhenOnNewIsRestored_Postgres`,
  `_ReplacedBodyBesideAnchorWhenOnNewIsRestored_Postgres`, `_FailingReadingFailsClosed_Postgres`,
  `TestSecretNodeCacheEpochIntegrity_FailingReadingFailsClosed_Postgres` (red on the PR's
  92d5148b1 head by behaviour), `_SystemMetadataUpkeepDoesNotFlush_Postgres`,
  `_SystemMetadataFenceTriggerIsLeftAlone_Postgres`,
  `_SystemMetadataFenceShapedTriggerOutsideSingleWriterIsRemovedAndFlushed_Postgres`,
  `_SystemMetadataFenceShapedTriggerOutsideSingleWriterSeenAtBoot_Postgres` (both red on the PR's
  first head by behaviour), `_SystemMetadataAnchorShadowedOperatorSeenAtBoot_Postgres`,
  `_SystemMetadataAnchorShadowedOperatorIsRemovedAndFlushed_Postgres`,
  `_InstallerReadingIgnoresShadowedSearchPath_Postgres` (red on the PR's 3f8937204 head by
  behaviour), `_SystemMetadataDecoyOperatorSeenAtBoot_Postgres`,
  `_SystemMetadataDecoyOperatorIsRemovedAndFlushed_Postgres`,
  `TestTriggerIntegrity_CatalogReadsIgnoreExactMatchOperators_Postgres` and
  `TestSecretNodeCacheEpochIntegrity_CatalogReadsIgnoreExactMatchOperators_Postgres` (class guard: a
  raising operator for every cross-type pair of catalog types pg_catalog has no exact operator for;
  red on the PR's c9506de59 head by behaviour),
  `TestRolePermGenerationIntegrity_ReadingPastTickDeadlineFailsClosed_Postgres` and
  `TestSecretNodeCacheEpochIntegrity_ReadingPastTickDeadlineFailsClosed_Postgres` (red on the PR's
  bc3739478 head by behaviour), `TestRolePermGenerationIntegrity_CancelledTickChangesNothing_Postgres`;
  `TestRolePermGenerationTarget_FenceAllowedOnlyInSingleWriterMode`
  (default CI); `TestFenceGuard_MatchesTheStore` (internal/solewriter, default CI).
