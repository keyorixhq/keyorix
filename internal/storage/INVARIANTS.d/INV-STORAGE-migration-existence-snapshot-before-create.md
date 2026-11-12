- **INV-STORAGE-migration-existence-snapshot-before-create** Every `tableExists` call written
  directly in `migrateDatabase`'s body runs in the one up-front snapshot, before any call there
  that can create a table with `AutoMigrate` (a direct `AutoMigrate`, or a migration step that
  reaches one). Why: `factory.go`'s snapshot comment and ADR-078. A table creation poisons the
  pgx prepared-statement cache, so a later `tableExists` can return a spurious false, and the
  step then re-runs a full `AutoMigrate` against a table already column-altered outside
  `AutoMigrate` (`INV-STORAGE-07`). Guard: `internal/storage`
  `TestMigrateDatabase_ExistenceSnapshotPrecedesEveryTableCreation` (go/parser over the package's
  non-test files, read only; the creating set is derived by call-graph fixpoint from `AutoMigrate`,
  with a population floor) and its red/green calibration
  `TestMigrationSnapshotOrderDetectsLateExistenceQuery`. **Not covered**: `tableExists` calls
  inside the migration steps themselves (`migrate_rbac.go`, `migrate_users.go`,
  `migrate_secrets.go` and the other `migrate_<domain>.go` files call it many times, after earlier
  steps may already have created tables; the guard looks only at calls written directly in
  `migrateDatabase`), that a new step is appended at the END of the list (true by construction),
  that a step's flag argument came from the snapshot, calls through function values, and the
  `INV-STORAGE-07` rule itself.
