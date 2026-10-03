# internal/storage invariants

Read this before changing anything in `internal/storage` (the factory/interface/migration
layer — SQLite vs. Postgres selection, schema epoch, migrations). See
`internal/storage/store/INVARIANTS.md` for the GORM-backed CRUD/locking primitives
underneath, and `internal/storage/models/INVARIANTS.md` notes folded into `store`'s file.

Format: `INV-STORAGE-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

## Schema epoch (ADR-097, ADR-101)

- **INV-STORAGE-01** An older binary refuses to start against a database migrated by a newer
  schema epoch. Why: ADR-097. Guard: `TestSchemaEpoch_NewerRecordedEpoch_RefusesToStart`.
- **INV-STORAGE-02** `currentSchemaEpoch` has not silently bumped past 1 without the
  accompanying ADR-101 compatibility-floor work landing — this is a deliberate tripwire, not a
  claim that raising the epoch is wrong. Guard: `schema_epoch_tripwire_test.go:TestCurrentSchemaEpoch_StillOne_SeeADR101`.
- **INV-STORAGE-03** A corrupt (non-integer) `schema_epoch` value in `system_metadata` fails
  closed (refuses boot), not proceed silently. Why: ADR-097 "Corrupt value" section. UNGUARDED
  (#issue: no test located beyond the two epoch tests above directly asserting this; likely
  covered incidentally by `checkSchemaEpoch`'s own tests — confirm and cite precisely, or add).
- **INV-STORAGE-04** Rolling back past a future `minCompatibleEpoch` floor must still refuse;
  an additive-safe migration must NOT raise that floor. Why: ADR-101 design (not yet
  implemented — `minCompatibleEpoch` does not exist in `system_metadata` yet). UNGUARDED
  (#issue: implement `minCompatibleEpoch` per ADR-101 before any migration that would need it).

## AutoMigrate completeness

- **INV-STORAGE-05** Every model struct in `models.go` appears in both
  `models.AllTestModels()` and `storage.AllModels()`/`migrateDatabase`'s AutoMigrate set — no
  model ships with handler code but no table. Why: #2258/#2264 (7, then 6, unmigrated tables
  found late). Guard: `all_models_migration_guard_test.go`
  (`TestAllTestModels_MatchesModelsGoStructSet`, `TestMigrateDatabase_EveryModelGetsATable_Fresh`,
  `_UpgradedInstall`, `_Postgres_Fresh`), `all_models_test.go:TestAllModels_MatchesLiveMigratedTables`.
- **INV-STORAGE-06** The 7 specific previously-unmigrated tables from #2258 exist after
  migration, including on an upgraded (not just fresh) install. Guard:
  `factory_seven_unmigrated_models_test.go` (`TestMigrateDatabase_CreatesAllSevenPreviouslyUnmigratedTables`,
  `_SurviveUpgradeRerun`) — a hand-picked regression pin, superseded in generality by
  INV-STORAGE-05 but kept.
- **INV-STORAGE-07** A full `AutoMigrate` is never run against a table already column-altered
  outside AutoMigrate (poisons the pgx prepared-statement cache, corrupts
  `information_schema` checks). Why: ADR-078, which itself states this is enforced only
  procedurally — by ~15 commented call sites in `factory.go`, not structurally. UNGUARDED by
  design, documented as such; do not add a structural guard without first reading ADR-078's
  own reasoning for why it declined one.

## Composite-key / index migrations

- **INV-STORAGE-08** `Role`'s composite PK is rebuilt to the full 4-column form on SQLite
  upgrade from either legacy 2-column or 3-column shapes, without losing rows mentioned outside
  the PK clause. Guard: `factory_rbac_pk_rebuild_test.go` (`TestRolePKIsComplete_SQLite_*`,
  `TestRebuildRolePKSQLite_*`, `TestRebuildRolePKIfNeeded_SQLite_EndToEnd/_AlreadyComplete`);
  Postgres sibling: `factory_rbac_pk_rebuild_postgres_test.go`.
- **INV-STORAGE-09** Creating a unique index (dynamic-secret-config name, project-membership,
  secret-node name, reminder-notification dedup, email, external-ID, username) fails loud, not
  silently drops rows, if pre-existing duplicate data would violate it. Guard:
  `factory_pre_existing_duplicate_index_test.go`
  (`TestDynamicSecretConfigNameIndex_FailsLoudOnPreExistingDuplicates`, `_FullBootHardFails...`,
  `TestProjectMembershipIndex_FailsLoudOnPreExistingDuplicates`,
  `TestReminderNotificationDedupIndex_FailsLoudOnPreExistingDuplicates/_NoDuplicates_CreatesIndex`);
  `secret_node_name_index_first_boot_test.go:TestEnsureSecretNodeNameIndex_PreExistingDuplicates_FailsLoudWithoutDeletingRows`.
- **INV-STORAGE-10** The secret-node-name unique index exists after a single fresh boot, and a
  concurrent same-name create race on first boot leaves exactly one survivor. Guard:
  `secret_node_name_index_first_boot_test.go`
  (`TestMigrateDatabase_SecretNodeUniqueIndex_ExistsAfterSingleFreshBoot`,
  `TestMigrateDatabase_ConcurrentCreateSecret_SameNameOnFirstBoot_ExactlyOneSurvives`).
- **INV-STORAGE-11** Email and external-ID partial unique indexes exclude soft-deleted rows,
  so a deleted user's email/external ID is reusable. Guard: `factory_identity_index_test.go`
  (`TestEmailPartialUniqueIndex`, `TestExternalIDPartialUniqueIndex`).
- **INV-STORAGE-12** Username partial unique index allows reuse after soft-delete. Guard:
  `factory_username_index_test.go:TestUsernamePartialUniqueIndex_ReuseAfterSoftDelete`.
- **INV-STORAGE-13** The break-glass "one active activation per project+user" partial index is
  created by migration. Guard: `factory_break_glass_index_test.go:TestBreakGlassActiveIndex_CreatedByMigration`.
- **INV-STORAGE-14** Companion/sibling indexes are created on upgrade, not only fresh install.
  Guard: `factory_companion_index_test.go:TestCompanionIndexes_CreatedOnUpgrade`.

## Backfills and fatal-migration discipline

- **INV-STORAGE-15** `AccountState` column values that are blank/NULL/whitespace are backfilled
  to a real enum value, excluding soft-deleted rows, idempotently. Why: #1723 ("don't trade
  loud failure for silent data loss"). Guard: `account_state_backfill_test.go`
  (`TestBackfillBlankAccountState_BackfillsBlankNullAndWhitespace`, `_ExcludesSoftDeletedRows`,
  `_IdempotentOnSecondRunAfterRealBackfill`, `_NoOpWhenNothingBlank`),
  `TestMigrateDatabase_FreshInstallBootsCleanlyWithAccountStateGuards`.
- **INV-STORAGE-16** The set of valid `AccountState` SQL values used by the storage-layer
  guard matches `internal/core`'s own account-state registry — no drift between the two. Guard:
  `account_state_backfill_core_sync_test.go:TestValidAccountStateSQLValues_MatchesCoreRegistry`.
- **INV-STORAGE-17** Every fatal migration step that can fail actually aborts
  `migrateDatabase`/boot on error — no swallowed error lets boot continue. Why: #G54 fail-closed
  discipline. Guard: `account_state_fatal_migration_guard_test.go`
  (`TestMigrateDatabase_AccountStateCallsAbortOnError`,
  `TestAccountStateMigrationScannerDetectsSwallowedErrors` — an AST-based scanner, not just a
  point test).
- **INV-STORAGE-18** A folded/normalized column backfill refuses (never silently merges) when
  two rows would collide after folding; scoped collisions (e.g. per-project) don't cross scope
  boundaries. Why: ADR corpus "normalization boundary design" (#1642). Guard:
  `normalize_backfill_test.go` (`TestBackfillFoldedColumn_RefusesOnCollision`,
  `TestNormalizeColumnInPlace_RefusesOnCollision`, `_ScopedCollision_DifferentProjectsNotAColliding`,
  `_ScopedCollision_SameProjectStillCollides`).

## Crash consistency

- **INV-STORAGE-19** A `migrateDatabase` crash mid-run on a fresh install does not leave the DB
  silently half-migrated on next boot — a retry completes every model's table. Guard:
  `factory_fresh_install_crash_test.go`
  (`TestFreshInstall_InterruptedAutoMigrateLoop_NextBootMustNotSilentlyStayHalfMigrated`,
  `TestFreshInstall_NoCrash_AllModelsPresent`); Postgres sibling:
  `factory_fresh_install_crash_postgres_test.go:TestFreshInstall_InterruptedAutoMigrateLoop_Postgres_NextBootSelfHeals`.
- **INV-STORAGE-20** Postgres migration against a non-public schema produces an identical
  result to the public-schema path. Guard:
  `migrate_postgres_nonpublic_schema_test.go:TestMigrateDatabase_Postgres_NonPublicSchemaMatchesPublic`.

## Path resolution (ADR-095)

- **INV-STORAGE-21** `database.path` resolves to an absolute path anchored at the config
  file's own directory, never process cwd; a `..` traversal in it fails `Load()` outright. Why:
  ADR-095. Guard: `TestLoad_DatabasePathResolvedAbsoluteRegardlessOfCwd`,
  `TestResolveConfigRelativePath_*`, `TestLoad_DatabasePathTraversal_Rejected` — these live in
  `internal/config`, not `internal/storage`, but gate `factory.go`'s `createLocalStorage` input
  directly.
- **INV-STORAGE-22** Opening a missing SQLite path should eventually refuse rather than
  silently create an empty DB. Why: ADR-095 "Task 3". UNGUARDED (#issue: `createLocalStorage`
  currently doesn't check for the file's prior existence; ADR-095 itself recommends this but it
  was not built).
- **INV-STORAGE-23** The SQLite migration lock should move inside the database
  (`BEGIN EXCLUSIVE`) instead of a file-based lock. Why: ADR-095 "Task 4.3". UNGUARDED (#issue:
  explicitly recommended by the ADR, not built).

## Connection / transaction hazards — SQLite

- **INV-STORAGE-24** The SQLite DSN sets `_txlock=immediate` (not the driver default
  `deferred`). Guard: `factory_sqlite_txlock_test.go` (`TestSqliteDSN_TxlockImmediate`,
  `TestSqliteDSN_PostgresPathUntouched`).
- **INV-STORAGE-25** `_txlock=immediate` closes the window where a deferred-transaction
  upgrade (read-then-write) fails `SQLITE_BUSY` despite `busy_timeout` being set. Guard:
  `factory_sqlite_deferred_upgrade_busy_test.go`
  (`TestSQLiteDeferredTransaction_UpgradeFailsBusyDespiteBusyTimeout` red control,
  `TestSQLiteImmediateTxlock_ClosesTheDeferredUpgradeBusyWindow` green).
- **INV-STORAGE-26** Required SQLite PRAGMAs (foreign_keys, WAL, etc.) are enabled on every
  fresh connection — GORM connection pooling can open new connections without re-applying
  them — and foreign-key enforcement actually rejects an orphan insert. Guard:
  `factory_sqlite_pragma_test.go` (`TestSQLitePragmas_EnabledOnFreshConnection`,
  `TestSQLiteForeignKeyEnforcement_RejectsOrphanInsert`).

## Connection / transaction hazards — Postgres

- **INV-STORAGE-27** `CreateStorage`/`OpenGormDB` against Postgres succeed on the happy path,
  and a migration failure during Postgres bootstrap propagates rather than being swallowed.
  Guard: `factory_postgres_bootstrap_test.go` (`TestCreateStorage_Postgres_Success`,
  `TestCreateStorage_Postgres_MigrationFailure_Propagates`, `TestOpenGormDB_Postgres_Success`).
- **INV-STORAGE-28** `pg_advisory_lock`/`pg_try_advisory_lock` is a live-connection primitive
  with zero cwd/filesystem dependency, unaffected by the ADR-095 path-resolution fix. Why:
  ADR-095 Task 2 table. Guard: documented-verified by direct code read in the ADR, not an
  independent test beyond the general Postgres bootstrap tests above.

- **INV-STORAGE-38** The default connection pool is per dialect and measured, not shared:
  `DefaultSQLiteMaxOpenConns` (8) and `DefaultPostgresMaxOpenConns` (25), with idle matching
  the effective open cap; an operator's `max_open_conns` always wins. Harnesses that must mirror
  production's pool reference the exported constants instead of copying a number. A Postgres pool
  larger than the server's usable slots (`max_connections - superuser_reserved_connections`) is
  logged at boot (it fails requests with SQLSTATE 53300). Why: #2631 (PERF-2), measurements in
  `docs/CONFIGURATION.md` "Connection pool". Guard: `pool_defaults_test.go`
  (`TestApplyPoolSettings_DialectDefaults`, `TestPostgresPoolHeadroomWarning`,
  `TestWarnPostgresPoolHeadroom_ReadsTheRealServerLimits` pg-gated); `BenchmarkPoolSize` for
  re-measuring.

## File permissions

- **INV-STORAGE-29** A freshly-created local SQLite database file is always mode 0600,
  regardless of the process's inherited umask. Why: #1647. Guard:
  `factory_local_storage_file_perms_test.go:TestCreateLocalStorage_FreshDatabase_AlwaysSecureModeRegardlessOfUmask`
  (umask 022/000 both exercised).
- **INV-STORAGE-30** A pre-existing SQLite file with lax permissions is tightened on open, not
  left as-is. Guard: `TestCreateLocalStorage_PreExistingLaxPermissions_TightenedOnOpen`.

## Tenancy / RLS (ADR-103) — largest open gap

- **INV-STORAGE-31** Postgres RLS as a second, independent tenancy layer: two DB roles
  (migrator with `BYPASSRLS`+ownership, runtime with neither), `FORCE ROW LEVEL SECURITY` on
  ~30 tables, `SET LOCAL app.current_tenant` per-transaction/per-statement, `WITH CHECK`
  mandatory on every policy, NULL/zero sentinel columns gated to platform-admin only. Why:
  ADR-103 (Accepted — **design only**). UNGUARDED (#issue: confirmed by direct grep — zero
  `ROW LEVEL SECURITY`/`app.current_tenant`/`keyorix_migrator` references anywhere in
  `internal/storage`. This is a ratified design with no implementation and no tests yet; the
  single largest gap found for this package).
- **INV-STORAGE-32** Every exported `LocalStorage`/`storage.Storage` method's first parameter
  is a real, threaded `context.Context` (never `context.Background()`/`context.TODO()`
  substituted) — required for RLS's `SET LOCAL` injection to ever reach the right tenant. Why:
  ADR-103 §1f "Guard". UNGUARDED (#issue: explicitly specified as required-before-ship, not
  built — blocks INV-STORAGE-31).
- **INV-STORAGE-33** SQLite has no RLS and is not protected by this layer at all
  (single-instance/dev only, per ADR-039). Why: ADR-103 §1e. Not a gap — by design.

## CLI / factory boundary (ADR-049, ADR-083)

- **INV-STORAGE-34** CLI commands obtain storage only via the factory (`InitializeStorage`) or
  the sanctioned `storage.OpenGormDB` raw-DB helper — SQLite/Postgres driver imports live only
  inside `internal/storage`. Why: ADR-049. Resolved more strongly than this invariant originally
  asked: since ADR-108's cli-server split, the `cli` module cannot import `internal/storage` (or
  `internal/core`/`internal/config`/`server/`) AT ALL — enforced via `go list -deps`, not source
  grep. Guard: `cli/internal/depguard/depguard_test.go:TestNoServerOrCloudSDKDependencies`. See
  `cli/INVARIANTS.md` INV-CLI-01.
- **INV-STORAGE-35** A process with `server.http.enabled`/`server.grpc.enabled` cannot boot on
  `storage.type: remote`. Why: ADR-083. Guard: `validateRemoteStorageNotServer`, which lives in
  `internal/config`, not `internal/storage` — noted here as an adjacent boundary this package's
  factory depends on, not this package's own test.
