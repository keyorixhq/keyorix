package storage

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

const (
	sqlCreateUniqueIdx = "CREATE UNIQUE INDEX IF NOT EXISTS "
	sqlWhereNotDeleted = "deleted_at IS NULL"
)

// migrationMu serializes migrateDatabase across goroutines IN THIS PROCESS (#266).
// startHTTPServer and startGRPCServer each independently call CreateStorage →
// migrateDatabase as separate goroutines when both HTTP and gRPC are enabled (a
// documented example config) — without this, both goroutines can observe a fresh
// database (`projectsExists == false`) and race the same CREATE TABLE/CREATE INDEX
// statements, with the loser erroring out and its server silently never starting
// listening (no crash, no alert). This does NOT protect against multiple separate
// OS processes/replicas migrating a shared Postgres concurrently — see
// postgresMigrationLockKey below for that.
var migrationMu sync.Mutex

// postgresMigrationLockKey is an arbitrary, fixed application-specific key for
// Postgres's session-level advisory lock (pg_advisory_lock/pg_advisory_unlock),
// used to serialize migrateDatabase ACROSS PROCESSES when running against
// Postgres (e.g. multiple replicas booting against a shared, fresh database).
// SQLite's cross-process equivalent is the write transaction withMigrationLock
// runs migrateDatabase inside (INV-STORAGE-23, ADR-095 Task 4.3).
const postgresMigrationLockKey = 872341

// migrationLockHeldHook, when non-nil, is invoked by withMigrationLock once
// every lock it takes is held, immediately before the migration itself runs.
// It is nil in every production build; only the cross-process migration-lock
// test installs it (factory_sqlite_migration_lock_indb_test.go), the same
// nil-in-production seam pattern as migrationCheckpoint below.
var migrationLockHeldHook func()

// migrationLockWorkDoneHook, when non-nil, is invoked by withMigrationLock
// right after the migration returns and still INSIDE every lock, so a
// timestamp taken here is strictly earlier than the lock's release and than
// any other process's entry into the migration. Nil in every production
// build; same test-only seam pattern as migrationLockHeldHook.
var migrationLockWorkDoneHook func()

// migrationCheckpoint, when non-nil, is invoked after each model is migrated in
// migrateDatabase's fresh-install-only bulk AutoMigrate loop, with a stable label
// naming the model just migrated. It is nil in every production build; only a
// crash-consistency test installs it (factory_fresh_install_crash_test.go), the
// same nil-in-production seam pattern as internal/encryption's rotationCheckpoint.
var migrationCheckpoint func(label string)

// migrationCheckpointHook invokes migrationCheckpoint if one is installed. A
// test's hook may panic to simulate a process crash at label; production passes
// through untouched.
func migrationCheckpointHook(label string) {
	if migrationCheckpoint != nil {
		migrationCheckpoint(label)
	}
}

// withMigrationLock runs fn while holding migrationMu (always) and an additional
// cross-process lock appropriate to the backend:
//   - Postgres: a session-level advisory lock (closing the cross-replica race
//     #266 describes, not just the in-process one). The advisory lock is
//     released in the same session it was acquired in, so this must run on a
//     single connection for the duration — acquired/released via db.Exec on the
//     same *gorm.DB, which GORM services from one checked-out *sql.Conn per call
//     only within an explicit transaction; to guarantee same-connection acquire/
//     release without depending on that, this wraps fn in db.Transaction.
//   - SQLite: the whole migration runs inside ONE write transaction on the
//     database itself (INV-STORAGE-23, ADR-095 Task 4.3; see
//     withSQLiteInDBMigrationLock). SQLite's own file lock then serializes
//     migrators across processes -- keyed on the database file, so it holds
//     however a process spells the path (a symlink or hard link to the same
//     file), whether or not a sidecar lock file survives, and for
//     MigrateExisting callers that pass no dbPath at all. The OS releases it
//     on crash, exactly like flock.
//   - Local SQLite (dbPath != ""), additionally and FIRST: a non-blocking
//     flock(2) sidecar lock on <dbPath>.migration.lock (#STORAGE-FACTORY-003),
//     kept as the fast path -- a second process using the SAME path still
//     fails immediately with an actionable error instead of waiting out
//     busy_timeout on the in-database lock. It is no longer what guarantees
//     serialization: it is keyed on the path string, not the file, so an
//     aliased path or a deleted sidecar slips past it (the in-database lock
//     above catches both). Acquired AFTER migrationMu so only one goroutine
//     in this process ever attempts it at a time — flock is scoped to the
//     open file description, not the process, so two concurrent in-process
//     goroutines contending for it directly (without migrationMu already
//     serializing them) would spuriously fail one against the other rather
//     than against a genuinely separate OS process.
func withMigrationLock(db *gorm.DB, isPostgres bool, dbPath string, fn func(*gorm.DB) error) error {
	return withMigrationLockPooled(db, isPostgres, false, dbPath, fn)
}

// withMigrationLockPooled is withMigrationLock with the Postgres lock's scope
// chosen by storage.database.pooler. xactLock (pooler: pgbouncer-transaction)
// takes pg_advisory_xact_lock instead of the session lock: it ends with the
// migration transaction however that transaction ends. The session lock's
// explicit unlock cannot run after a failed migration statement (the
// transaction is aborted), so a session lock would stay on the server
// connection; on a direct connection that connection ends with the process,
// but a transaction-mode pooler hands the server connection, lock included,
// to its next client.
func withMigrationLockPooled(db *gorm.DB, isPostgres, xactLock bool, dbPath string, fn func(*gorm.DB) error) error {
	migrationMu.Lock()
	defer migrationMu.Unlock()

	run := func(h *gorm.DB) error {
		if migrationLockHeldHook != nil {
			migrationLockHeldHook()
		}
		err := fn(h)
		if migrationLockWorkDoneHook != nil {
			migrationLockWorkDoneHook()
		}
		return err
	}

	if isPostgres {
		return db.Transaction(func(tx *gorm.DB) error {
			if xactLock {
				if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", postgresMigrationLockKey).Error; err != nil {
					return fmt.Errorf("acquire migration advisory lock: %w", err)
				}
				return run(tx)
			}
			if err := tx.Exec("SELECT pg_advisory_lock(?)", postgresMigrationLockKey).Error; err != nil {
				return fmt.Errorf("acquire migration advisory lock: %w", err)
			}
			defer tx.Exec("SELECT pg_advisory_unlock(?)", postgresMigrationLockKey)
			return run(tx)
		})
	}

	if dbPath != "" {
		osLock, err := acquireSQLiteMigrationLock(dbPath)
		if err != nil {
			return err
		}
		defer osLock.release()
	}
	return withSQLiteInDBMigrationLock(db, dbPath, run)
}

// gormConfig returns the *gorm.Config shared by every gorm.Open call in this
// package. GORM's zero-value Config leaves its default Warn-level logger active,
// which interpolates bound query-parameter VALUES into the logged SQL statement
// whenever a query errors or exceeds the slow-query threshold — meaning secret
// ciphertext, token hashes, and other sensitive bound parameters would otherwise
// get written to stdout/logs on any query error or slow query. Silence it here
// so that never happens by default (#464).
//
// QueryFields makes every model read select its columns by name instead of
// SELECT *. During a rolling upgrade, release N-1 replicas keep running against a
// schema release N already migrated; a star-expanded plan then fails (Postgres
// SQLSTATE 0A000, "cached plan must not change result type") or silently scans a
// shape it never saw. Named columns make an added column invisible to N-1
// (INV-STORE-explicit-column-reads).
func gormConfig() *gorm.Config {
	return &gorm.Config{Logger: logger.Default.LogMode(logger.Silent), QueryFields: true}
}

// StorageFactory creates storage instances based on configuration
type StorageFactory interface {
	CreateStorage(config *config.Config) (storage.Storage, error)
}

// DefaultStorageFactory is the default implementation of StorageFactory
type DefaultStorageFactory struct{}

// NewStorageFactory creates a new storage factory
func NewStorageFactory() StorageFactory {
	return &DefaultStorageFactory{}
}

// storageBackend is one storage.type implementation: the storage.type values
// that select it and its constructor.
type storageBackend struct {
	names  []string
	create func(f *DefaultStorageFactory, cfg *config.Config) (storage.Storage, error)
}

// storageBackends is every backend CreateStorage can select, in match order (the
// names are disjoint, so the order only fixes where a lookup stops). A new
// backend is one factory_<backend>.go file declaring its storageBackend plus one
// line here.
var storageBackends = []storageBackend{postgresBackend, localBackend}

// CreateStorage creates a storage instance based on the configuration
func (f *DefaultStorageFactory) CreateStorage(cfg *config.Config) (storage.Storage, error) {
	for _, b := range storageBackends {
		if slices.Contains(b.names, cfg.Storage.Type) {
			return b.create(f, cfg)
		}
	}
	switch cfg.Storage.Type {
	case "":
		// #G-blank-storage-default: a blank storage.type must never silently
		// fall through to local SQLite storage -- this is the same "blank/
		// zero-value treated as an implicit permissive default" defect shape
		// as the AccountState ""->Active auth-bypass bug (#1741/#1742). Before
		// this fix, "local", "sqlite", "" were one case, so a config file with
		// no storage: block at all (or a hand-built *config.Config{} zero
		// value) silently created a real, on-disk local database file with no
		// operator-visible signal -- indistinguishable from an operator who
		// explicitly chose local storage.
		//
		// The ONE legitimate "no storage: block in the config = local SQLite"
		// deployment shape (an existing on-prem single-node server) is
		// preserved, but NOT here: server/main.go's initializeCoreService (and
		// main() itself, before its own first cfg.Validate() call) explicitly
		// sets cfg.Storage.Type = "local" in the server's own boot sequence,
		// before this factory or Config.Validate() ever sees the config. That
		// keeps the default scoped to the one caller allowed to apply it. Every
		// OTHER caller -- CLI commands (internal/cli/common.InitializeStorage/
		// InitializeCoreService deliberately do NOT set this default), test
		// fixtures that build a config.Config{} zero value, and any future
		// caller -- must now see a loud, explicit error instead of a silent
		// local database.
		return nil, fmt.Errorf("storage.type is not set: no storage configuration found -- specify \"local\", \"postgres\", or \"postgresql\" explicitly")
	default:
		// #463: defense in depth. Config.Validate() rejects an unrecognized
		// storage.type at boot, but this factory can also be invoked directly
		// (e.g. by tests or other code paths that don't call Validate() first)
		// — a typo like "postgress" must never silently fall back to SQLite,
		// since in a multi-replica HA deployment intending shared Postgres
		// that produces per-replica split-brain SQLite instances with no
		// operator-visible signal. "remote" is also caught here now:
		// RemoteStorage was deleted entirely in ADR-108 Phase 6 step 14b-2.
		return nil, fmt.Errorf("invalid storage.type %q: must be one of \"local\", \"postgres\", or \"postgresql\"", cfg.Storage.Type)
	}
}

// afterMigrateHook is nil in every build except `-tags nplus1`
// (factory_nplus1_hook.go), where it adds one extra column to every table so the
// suites can prove the current binary tolerates a schema one release ahead
// (QUERYFIELDS-1, INV-STORE-explicit-column-reads). Nothing in production sets it.
var afterMigrateHook func(db *gorm.DB) error

func runAfterMigrateHook(db *gorm.DB) error {
	if afterMigrateHook == nil {
		return nil
	}
	return afterMigrateHook(db)
}

// columnExists reports whether table already has column, branching on the
// dialect like indexExists below: information_schema on Postgres, but SQLite
// has no information_schema at all — querying it there returns a "no such
// table" driver error that this Raw().Scan() call was silently swallowing
// (Scan's error return was never checked), so columnExists was unconditionally
// returning false for every SQLite deployment (the default "local" storage
// backend). Every `columnExists(...) && ...`-gated ALTER TABLE ADD COLUMN
// below was consequently silently unreachable on SQLite; a fresh installs
// still get the column via models.X{}'s own struct tag through AutoMigrate,
// masking the gap, but any additive column that (like several here) is only
// ever added via this raw-SQL path and never via a struct tag would silently
// never reach an existing SQLite database. pragma_table_info is a builtin
// table-valued function on both the CGO (mattn) and pure-Go SQLite drivers.
//
// Postgres schema scoping (#1980): columnExists, tableExists, indexExists and
// rolePKIsComplete all filter on current_schema() -- the schema GORM itself
// creates into and inspects (its Postgres migrator's HasTable/HasIndex filter
// on CURRENT_SCHEMA()). They previously hard-coded 'public' (tableExists,
// rolePKIsComplete) or applied no schema filter at all (columnExists,
// indexExists), so on any connection whose current_schema() isn't public
// (a search_path DSN parameter, a role-level search_path, a "$user" schema)
// every tableExists-gated index/constraint was silently skipped, and an
// object of the same name in ANOTHER schema could satisfy the check. No
// change for the default deployment, where current_schema() = 'public'.
func columnExists(db *gorm.DB, table, column string) bool {
	var count int64
	if db.Dialector.Name() == "postgres" {
		db.Raw("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ? AND column_name = ?", table, column).Scan(&count)
	} else {
		db.Raw("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?", table, column).Scan(&count)
	}
	return count > 0
}

// tableExists checks whether a table exists without relying on GORM's HasTable
// (which can fail with "insufficient arguments" on some Postgres driver
// versions). See columnExists's doc comment: this had the identical SQLite gap
// (information_schema.tables doesn't exist there, so the query errored and the
// unchecked Scan silently left count at its zero value) — every
// `tableExists(...)`-gated block, including the ensureDynamicSecretConfigNameIndex
// and ensureProjectMembershipIndex calls this same file makes below, was
// unconditionally skipped on every SQLite ("local" storage) deployment, which
// is the default backend. That means the very unique indexes this file (and
// the #490 fix in particular) exists to create were never actually being
// created on SQLite at all.
func tableExists(db *gorm.DB, table string) bool {
	var count int64
	if db.Dialector.Name() == "postgres" {
		db.Raw("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = ?", table).Scan(&count)
	} else {
		db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&count)
	}
	return count > 0
}

// schemaCheckRefusal marks a refusal of checkSchemaEpoch inside migrateDatabase.
// That check runs before any migration step, so migrateError reports it as what
// it is instead of as "failed to migrate database" (BOOT-REFUSALS-1 item 6:
// operators went looking for a migration error). The message is the check's own.
type schemaCheckRefusal struct{ err error }

func (e *schemaCheckRefusal) Error() string { return e.err.Error() }
func (e *schemaCheckRefusal) Unwrap() error { return e.err }

// migrateError wraps an error of the migration step for the start-up message.
func migrateError(err error) error {
	if _, ok := errors.AsType[*schemaCheckRefusal](err); ok {
		return fmt.Errorf("database schema check failed (checked before migrating; nothing was migrated): %w", err)
	}
	return fmt.Errorf("failed to migrate database: %w", err)
}

// indexExists reports whether a database index with the given name already
// exists. The ensure*Index helpers below gate their one-time, pre-existing-
// duplicate-row scan (#490) on this: once the target unique index is in place,
// duplicates can no longer accumulate under it, so re-scanning the whole table
// for duplicates on every subsequent boot (once the index already exists) would
// be pure wasted work. There is no single portable information_schema view for
// indexes the way tableExists/columnExists have for tables/columns, so this
// branches on the dialect explicitly: pg_indexes on Postgres, sqlite_master on
// SQLite.
func indexExists(db *gorm.DB, indexName string) bool {
	var count int64
	if db.Dialector.Name() == "postgres" {
		db.Raw("SELECT COUNT(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ?", indexName).Scan(&count)
	} else {
		db.Raw("SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?", indexName).Scan(&count)
	}
	return count > 0
}

// warnIfDuplicatesExist checks whether pre-existing rows already violate the
// unique constraint about to be created and, if so, returns a clear, actionable
// error instead of letting the bare CREATE UNIQUE INDEX fail later with an
// opaque driver-level "duplicate key"/"UNIQUE constraint failed" message
// (#490). whereClause mirrors a partial index's own predicate (e.g.
// sqlWhereNotDeleted); pass "" for a plain, non-partial index.
//
// This never deletes or modifies any row. Every ensure*Index helper below uses
// this rather than an auto-delete/dedup pass: a row that collides on the new
// unique key is never guaranteed to be a redundant repeat of the same event —
// for every one of these tables, the non-key columns (an encrypted secret
// value, a permission level, a role, an admin DSN, an account's password hash
// and MFA config, a project's child secrets/environments) can legitimately
// differ between the colliding rows, so an arbitrary "keep the lowest id"
// tie-break could silently destroy the one that was actually correct/current
// with zero operator visibility. Resolving a genuine conflict is therefore
// left to a deliberate operator decision made through the application's own
// APIs (which record a proper audit entry), not an unattended migration
// script. This still fails the boot on a genuine conflict (same outcome as
// before this fix), but with a message that tells the operator exactly what to
// do, instead of an opaque constraint-violation error surfacing from deep
// inside a later CREATE INDEX statement.
func warnIfDuplicatesExist(db *gorm.DB, table, keyExpr, whereClause, remediation string) error {
	groupFilter := ""
	if whereClause != "" {
		groupFilter = " WHERE " + whereClause
	}
	var dupGroups int64
	query := fmt.Sprintf(
		"SELECT COUNT(*) FROM (SELECT %s FROM %s%s GROUP BY %s HAVING COUNT(*) > 1) dupes",
		keyExpr, table, groupFilter, keyExpr,
	)
	if err := db.Raw(query).Scan(&dupGroups).Error; err != nil {
		return fmt.Errorf("failed to check %s for pre-existing duplicates: %w", table, err)
	}
	if dupGroups > 0 {
		predicate := whereClause
		if predicate == "" {
			predicate = "(no predicate — every row is in scope)"
		}
		return fmt.Errorf("cannot create unique index on %s (%s): %d pre-existing group(s) of rows already share a value under %q — %s",
			table, keyExpr, dupGroups, predicate, remediation)
	}
	return nil
}

// rolePKIsComplete reports whether the given role-assignment table already has the
// full composite PK: (user_id/group_id, role_id, project_id, environment_id).
// Detection is dialect-specific:
//   - SQLite: query pragma_table_info(<table>) (the actual parsed schema SQLite
//     itself resolved, exposed as a table-valued function — the same mechanism
//     this codebase's Migrator.HasColumn already uses) and check the `pk` column
//     — nonzero for every column that is actually a member of the table's
//     primary key — for project_id and environment_id. This was previously a
//     substring match against everything from the first "primary key" occurrence
//     in the raw CREATE TABLE text to the end of the statement (#STORAGE-FACTORY-002):
//     correct only by coincidence of where ALTER TABLE ADD COLUMN happens to place
//     new columns relative to a trailing table-level PRIMARY KEY constraint, and
//     it would false-positive (silently skipping the PK rebuild, leaving the
//     narrower old PK in place) on any DDL where "project_id"/"environment_id"
//     appear after "primary key" for an unrelated reason — e.g. in a trailing
//     CHECK or FOREIGN KEY constraint that mentions those columns without them
//     being PK members. Querying the parsed schema directly makes this immune to
//     DDL text layout entirely.
//   - Postgres: query information_schema.key_column_usage for the table's PK and
//     check that both columns appear among the PK members.
func rolePKIsComplete(db *gorm.DB, table string) bool {
	if db.Dialector.Name() == "postgres" {
		var count int64
		db.Raw(`
			SELECT COUNT(*) FROM information_schema.key_column_usage
			WHERE table_schema = current_schema()
			  AND table_name   = ?
			  AND constraint_name IN (
				SELECT constraint_name
				FROM   information_schema.table_constraints
				WHERE  table_schema     = current_schema()
				  AND  table_name       = ?
				  AND  constraint_type  = 'PRIMARY KEY'
			  )
			  AND column_name IN ('project_id', 'environment_id')`,
			table, table).Scan(&count)
		return count >= 2
	}
	// SQLite: ask SQLite's own parsed schema which columns are PK members,
	// rather than text-matching the raw CREATE TABLE statement.
	var count int64
	db.Raw(
		"SELECT COUNT(*) FROM pragma_table_info(?) WHERE pk > 0 AND name IN ('project_id', 'environment_id')",
		table,
	).Scan(&count)
	return count >= 2
}

// rebuildRolePKIfNeeded detects whether user_roles / group_roles still carry the
// old (user_id, role_id) or (user_id, role_id, project_id) primary key and, if so,
// rebuilds the table with the correct four-column composite PK
// (user_id/group_id, role_id, project_id, environment_id). By the time this runs,
// the Phase 2 block above has already added environment_id (if absent) and
// normalised NULL project_id values to 0, so all data is clean.
//
// SQLite does not support ALTER TABLE DROP/ADD CONSTRAINT, so the rebuild is done
// via CREATE TABLE … AS SELECT / DROP / RENAME, wrapped in a transaction.
// Postgres supports DROP CONSTRAINT / ADD CONSTRAINT in a single DDL statement.
//
// Idempotent: if the PK is already correct, nothing is done.
func rebuildRolePKIfNeeded(db *gorm.DB) error {
	type tableSpec struct {
		name   string // table name
		idCol  string // first PK column (user_id or group_id)
		pkCols string // full new PK column list for CREATE TABLE
		oldPK  string // old PK constraint name on Postgres (heuristic)
	}
	tables := []tableSpec{
		{
			name:   "user_roles",
			idCol:  "user_id",
			pkCols: "user_id, role_id, project_id, environment_id",
			oldPK:  "user_roles_pkey",
		},
		{
			name:   "group_roles",
			idCol:  "group_id",
			pkCols: "group_id, role_id, project_id, environment_id",
			oldPK:  "group_roles_pkey",
		},
	}

	for _, spec := range tables {
		if !tableExists(db, spec.name) {
			continue
		}
		if rolePKIsComplete(db, spec.name) {
			continue
		}

		if db.Dialector.Name() == "postgres" {
			if err := rebuildRolePKPostgres(db, spec.name, spec.idCol, spec.pkCols, spec.oldPK); err != nil {
				return fmt.Errorf("PK rebuild for %s (postgres): %w", spec.name, err)
			}
		} else {
			if err := rebuildRolePKSQLite(db, spec.name, spec.idCol, spec.pkCols); err != nil {
				return fmt.Errorf("PK rebuild for %s (sqlite): %w", spec.name, err)
			}
		}
	}
	return nil
}

// rebuildRolePKSQLite recreates table on SQLite with the correct composite PK.
// SQLite does not support DROP/ADD CONSTRAINT, so a CREATE/INSERT/DROP/RENAME
// sequence is used. The Phase 2 column-add block runs before this, but we guard
// defensively: if project_id or environment_id are absent (truly ancient schemas)
// we substitute the literal 0, so the rebuild is self-contained regardless of
// what prior migration steps managed to run.
func rebuildRolePKSQLite(db *gorm.DB, table, idCol, pkCols string) error {
	newTable := table + "_new"
	hasExpiresAt := columnExists(db, table, "expires_at")
	hasProjectID := columnExists(db, table, "project_id")
	hasEnvID := columnExists(db, table, "environment_id")

	return db.Transaction(func(tx *gorm.DB) error {
		// Build column list for SELECT: substitute 0 for columns not yet present.
		projectExpr := "0"
		if hasProjectID {
			projectExpr = "COALESCE(project_id, 0)"
		}
		envExpr := "0"
		if hasEnvID {
			envExpr = "COALESCE(environment_id, 0)"
		}
		selectCols := fmt.Sprintf(
			"COALESCE(%s, 0), COALESCE(role_id, 0), %s, %s",
			idCol, projectExpr, envExpr,
		)
		createExpiresCol := ""
		if hasExpiresAt {
			selectCols += ", expires_at"
			createExpiresCol = ",\n\t\texpires_at TIMESTAMP WITH TIME ZONE"
		}

		createSQL := fmt.Sprintf(`CREATE TABLE %s (
		%s INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		project_id INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0%s,
		PRIMARY KEY (%s)
	)`, newTable, idCol, createExpiresCol, pkCols)

		if err := tx.Exec(createSQL).Error; err != nil {
			return fmt.Errorf("create %s: %w", newTable, err)
		}

		insertSQL := fmt.Sprintf("INSERT INTO %s SELECT %s FROM %s", newTable, selectCols, table)
		if err := tx.Exec(insertSQL).Error; err != nil {
			return fmt.Errorf("copy rows into %s: %w", newTable, err)
		}

		if err := tx.Exec(fmt.Sprintf("DROP TABLE %s", table)).Error; err != nil {
			return fmt.Errorf("drop old %s: %w", table, err)
		}

		if err := tx.Exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", newTable, table)).Error; err != nil {
			return fmt.Errorf("rename %s to %s: %w", newTable, table, err)
		}

		return nil
	})
}

// rebuildRolePKPostgres rebuilds the PK on Postgres by ensuring project_id /
// environment_id columns exist (with default 0 if not yet present — belt-and-
// suspenders after the Phase 2 block), then dropping the old constraint and adding
// the new four-column one.
func rebuildRolePKPostgres(db *gorm.DB, table, idCol, pkCols, oldConstraint string) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Belt-and-suspenders: add missing columns (Phase 2 already did this,
		// but guard here too so this function is self-contained).
		for _, col := range []string{"project_id", "environment_id"} {
			if !columnExists(tx, table, col) {
				if err := tx.Exec(fmt.Sprintf(
					"ALTER TABLE %s ADD COLUMN %s INTEGER NOT NULL DEFAULT 0", table, col,
				)).Error; err != nil {
					return fmt.Errorf("add %s.%s: %w", table, col, err)
				}
			}
		}

		// Normalise any remaining NULLs (should be 0 already after Phase 2).
		tx.Exec(fmt.Sprintf("UPDATE %s SET project_id = 0 WHERE project_id IS NULL", table))
		tx.Exec(fmt.Sprintf("UPDATE %s SET environment_id = 0 WHERE environment_id IS NULL", table))

		// Drop the old PK constraint. Use IF EXISTS (Postgres 9.5+) so this is safe
		// even if the constraint name was customised.
		if err := tx.Exec(fmt.Sprintf(
			"ALTER TABLE %s DROP CONSTRAINT IF EXISTS %s", table, oldConstraint,
		)).Error; err != nil {
			return fmt.Errorf("drop old PK on %s: %w", table, err)
		}

		// Add the new four-column PK.
		if err := tx.Exec(fmt.Sprintf(
			"ALTER TABLE %s ADD PRIMARY KEY (%s)", table, pkCols,
		)).Error; err != nil {
			return fmt.Errorf("add new PK on %s (%s): %w", table, pkCols, err)
		}

		return nil
	})
}

// migrateDatabase performs database migrations via GORM AutoMigrate.
// Idempotent: safe to run on both fresh and existing databases.
// On a fresh DB, AutoMigrate creates all tables. On an existing DB,
// it adds missing columns and indexes without dropping anything.
func (f *DefaultStorageFactory) migrateDatabase(db *gorm.DB) error { // NOSONAR -- cognitive complexity 266, suppress go:S3776
	// ADR-097: refuse before touching anything if this binary is older than
	// the database it's pointed at -- must run before every other step below.
	if err := checkSchemaEpoch(db); err != nil {
		return &schemaCheckRefusal{err: err}
	}
	// The pipelined audit commit needs the audit_events id sequence to be
	// CACHE 1; refuse to start rather than fail every audit write later.
	if err := store.CheckAuditIDSequenceCache(db); err != nil {
		return err
	}
	// #G54: every additive column/index migration below is now checked and
	// propagated (fail-closed) via this helper, instead of the bare
	// db.Exec(...) each previously used — which discarded the result
	// entirely. A silently-failed ALTER for a security-relevant column
	// (account_state, mfa_enabled, failed_login_attempts, login_locked_until,
	// ...) would let the app boot as if the migration succeeded, only to hard
	// -fail (or silently no-op) the first time application code reads or
	// writes that column, far from the actual root cause. Mirrors this same
	// function's own AutoMigrate/Migrator.AddColumn calls below, which
	// already check and wrap their errors.
	exec := func(sql string) error {
		if err := db.Exec(sql).Error; err != nil {
			return fmt.Errorf("migration failed (%s): %w", sql, err)
		}
		return nil
	}
	// Migration steps, part 1 (every boot, before the table snapshot below): additive
	// changes to tables an existing database already has, each a no-op on a fresh one.
	// How to add a migration step: write it in the domain's migrate_<domain>.go, gated on
	// tableExists/columnExists so it is idempotent, taking db (and exec) as parameters;
	// call it at the END of this list (never reorder existing steps); bump
	// currentSchemaEpoch if it changes the schema.
	if err := alterSecretNodes(db, exec); err != nil {
		return err
	}
	// DEK-SWEEP-CACHE-1: secret_versions.cache_epoch, the latest-version cache
	// generation term the DEK sweep raises. UPGRADE call site (a fresh install gets
	// the column from models.SecretVersion; the tail below covers that path too).
	// No-op until secret_versions exists.
	if err := store.EnsureSecretVersionCacheEpoch(db); err != nil {
		return err
	}
	// #3259: the triggers that move role_permissions_generation on every write to
	// role_permissions/permissions, direct SQL included. The UPGRADE call site,
	// for the same reason as cache_epoch's above (the tail below only runs on a
	// fresh or half-migrated install); a no-op until the tables exist.
	if err := store.EnsureRolePermissionsGenerationTriggers(db); err != nil {
		return err
	}
	// #3362: clear the suspend clear-copies marker on every status change away
	// from suspended, an older binary's included (upgrade call site).
	if err := store.EnsureSecretSuspendMarkerTrigger(db); err != nil {
		return err
	}
	// #3359: an older binary's purge must not replace the v2 retention anchor.
	if err := store.EnsureAuditRetentionAnchorTrigger(db); err != nil {
		return err
	}
	if err := alterAnomalyAlerts(db, exec); err != nil {
		return err
	}
	// models.SecretAccessLog's indexes (store.SecretAccessLogIndexes) are built by
	// the audit index step after this migration (SQLite: migrateSQLite;
	// Postgres: ensureAuditListIndexesPostgres, CONCURRENTLY), not here.

	if err := alterUsers(db, exec); err != nil {
		return err
	}

	if err := alterSessionDeviceColumns(db, exec); err != nil {
		return err
	}

	if err := alterAuditEvents(db, exec); err != nil {
		return err
	}

	if err := alterSessionImpersonationColumns(db, exec); err != nil {
		return err
	}

	if err := alterRoleAssignmentScope(db, exec); err != nil {
		return err
	}

	if err := alterRoleFlags(db, exec); err != nil {
		return err
	}

	// RBAC PK rebuild: fresh installs get the full composite PK (user_id, role_id,
	// project_id, environment_id) via AutoMigrate, but existing GORM-created DBs
	// keep their old (user_id, role_id) or (user_id, role_id, project_id) PK — so
	// the same role cannot be assigned at two different project/environment scopes
	// on an upgraded install. Detect the old PK and rebuild it (SQLite requires a
	// table recreation; Postgres can drop + add the constraint in-place), run after
	// the Phase 2 ADD COLUMN / NULL-normalise so the data is clean before we touch
	// the PK.
	if err := rebuildRolePKIfNeeded(db); err != nil {
		return err
	}

	// Snapshot all table-existence checks UP FRONT, before any AutoMigrate runs.
	// AutoMigrate creating a new table poisons the pgx connection's prepared-statement
	// cache, so a subsequent parameterized information_schema query (tableExists) can
	// spuriously return false ("insufficient arguments") — which would then re-run the
	// full AutoMigrate against an existing DB and fail. Capturing the flags first means
	// no existence query runs after a creation. (Both rotation_policies and
	// personal_access_tokens are kept out of the full AutoMigrate list below for the
	// same pgx reason — see the NOTE there.)
	projectsExists := tableExists(db, "projects")
	rotationExists := tableExists(db, "rotation_policies")
	patExists := tableExists(db, "personal_access_tokens")
	invitationsExists := tableExists(db, "project_invitations")
	accessReqExists := tableExists(db, "access_requests")
	accessReqApprovalsExists := tableExists(db, "access_request_approvals")
	rejectionReasonTemplateExists := tableExists(db, "rejection_reason_templates")
	campaignExists := tableExists(db, "access_review_campaigns")
	breakGlassExists := tableExists(db, "break_glass_activations")
	legalHoldExists := tableExists(db, "legal_holds")
	riskExceptionExists := tableExists(db, "risk_exceptions")
	ssoLoginStateExists := tableExists(db, "sso_login_states")
	schedulerLockLeaseExists := tableExists(db, "scheduler_lock_leases")
	sodExists := tableExists(db, "sod_policies")
	secretDepExists := tableExists(db, "secret_dependencies")
	pwHistExists := tableExists(db, "password_histories")
	machineExists := tableExists(db, "machine_identities")
	machineCredExists := tableExists(db, "machine_identity_credentials")
	machineRoleExists := tableExists(db, "machine_identity_roles")
	machineOIDCExists := tableExists(db, "machine_identity_oidc_bindings")
	membershipExists := tableExists(db, "project_memberships")
	setupTokenExists := tableExists(db, "setup_tokens")
	notificationsExists := tableExists(db, "notifications")
	mfaSecretExists := tableExists(db, "mfa_secrets")
	mfaRecoveryExists := tableExists(db, "mfa_recovery_codes")
	mfaChallengeExists := tableExists(db, "mfa_challenges")
	mfaStepUpGrantExists := tableExists(db, "mfa_step_up_grants")
	dynConfigExists := tableExists(db, "dynamic_secret_configs")
	dynLeaseExists := tableExists(db, "dynamic_secret_leases")
	webauthnCredExists := tableExists(db, "web_authn_credentials")
	webauthnSessExists := tableExists(db, "web_authn_sessions")
	loginAttemptExists := tableExists(db, "login_attempts")
	auditCkptExists := tableExists(db, "audit_checkpoints")
	connectRefGrantExists := tableExists(db, "connect_ref_grants")
	connectorProjectBindingsExists := tableExists(db, "connector_project_bindings")
	groupsExists := tableExists(db, "groups")
	// The remaining flags below back freshInstallComplete (see its own doc
	// comment, near the former `if projectsExists { return nil }` gate):
	// every one of them is a model migrated by the fresh-install-only
	// transactional block, snapshotted up front for the exact same pgx
	// reason as every flag above -- these must never be queried AFTER any
	// AutoMigrate call in this function, including the ones inside that
	// block itself.
	environmentExists := tableExists(db, "environments")
	userExists := tableExists(db, "users")
	roleExists := tableExists(db, "roles")
	permissionExists := tableExists(db, "permissions")
	rolePermissionExists := tableExists(db, "role_permissions")
	userRoleExists := tableExists(db, "user_roles")
	userGroupExists := tableExists(db, "user_groups")
	groupRoleExists := tableExists(db, "group_roles")
	secretNodeExists := tableExists(db, "secret_nodes")
	secretVersionExists := tableExists(db, "secret_versions")
	shareRecordExists := tableExists(db, "share_records")
	sessionExists := tableExists(db, "sessions")
	tagExists := tableExists(db, "tags")
	secretTagExists := tableExists(db, "secret_tags")
	auditEventExists := tableExists(db, "audit_events")
	systemMetadataExists := tableExists(db, "system_metadata")
	anomalyAlertExists := tableExists(db, "anomaly_alerts")
	anomalyConfigRecordExists := tableExists(db, "anomaly_config_records")
	statsSnapshotExists := tableExists(db, "stats_snapshots")
	deploymentStatsSnapshotExists := tableExists(db, "deployment_stats_snapshots")
	secretACLExists := tableExists(db, "secret_acls")
	scheduleExists := tableExists(db, "secret_access_schedules")
	pendingAuditExists := tableExists(db, "pending_audit_events")
	secretTemplateExists := tableExists(db, "secret_templates")
	alertEscalationExists := tableExists(db, "alert_escalation_policies")
	secretVersionCommentExists := tableExists(db, "secret_version_comments")
	mfaStepupTokenExists := tableExists(db, "mfa_stepup_tokens")
	hygieneTrendExists := tableExists(db, "hygiene_trend_snapshots")
	compliancePostureExists := tableExists(db, "compliance_posture_snapshots")
	// SESSION-U guard U1: these 11 were only ever reached via the fresh-install-only
	// bulk AutoMigrate loop below (guarded on !projectsExists), so an install that
	// upgrades from any older binary — i.e. every existing production deployment —
	// never gets these tables at all. secret_access_logs is the live one that
	// matters most: writeAccessLog (internal/core/audit.go) is called on every
	// secret read/create/update/rotate/delete and only logs the failure, so the
	// entire secret-access audit trail silently stops recording on any upgraded
	// install, forever, with no error surfaced to a caller. api_clients/api_tokens/
	// password_resets back the `keyorix admin encryption` sweep/rotate/validate
	// commands (internal/encryptionops/auth_encryption.go), which would hard-fail
	// with "no such table" the first time an operator ran them post-upgrade. The
	// rest (api_call_logs, external_identities, g_rpc_services, identity_providers,
	// rate_limits, secret_metadata_histories, settings) have no live caller left
	// anywhere in the tree today, but get the same fix for consistency and because
	// the guard test treats every models.go struct alike.
	apiClientExists := tableExists(db, "api_clients")
	apiTokenExists := tableExists(db, "api_tokens")
	apiCallLogExists := tableExists(db, "api_call_logs")
	externalIdentityExists := tableExists(db, "external_identities")
	grpcServiceExists := tableExists(db, "g_rpc_services")
	identityProviderExists := tableExists(db, "identity_providers")
	passwordResetExists := tableExists(db, "password_resets")
	rateLimitExists := tableExists(db, "rate_limits")
	secretAccessLogExists := tableExists(db, "secret_access_logs")
	secretMetadataHistoryExists := tableExists(db, "secret_metadata_histories")
	settingExists := tableExists(db, "settings")

	// Migration steps, part 2 (every boot, after the snapshot): create a table an
	// existing database is missing, or add columns to one it has via the Migrator.
	// How to add a migration step: add the table's flag to the snapshot above (never call
	// tableExists after an AutoMigrate), write the step in migrate_<domain>.go taking db
	// and the flags it reads as parameters, call it at the END of this list, and bump
	// currentSchemaEpoch.
	if err := createRotationPolicies(db, rotationExists); err != nil {
		return err
	}

	if err := createPersonalAccessTokens(db, patExists); err != nil {
		return err
	}

	if err := createMFATables(db, mfaSecretExists, mfaRecoveryExists, mfaChallengeExists, mfaStepUpGrantExists); err != nil {
		return err
	}

	if err := createDynamicSecretTables(db, exec, dynConfigExists, dynLeaseExists); err != nil {
		return err
	}

	if err := createWebAuthnTables(db, webauthnCredExists, webauthnSessExists); err != nil {
		return err
	}

	if err := createLoginAttempts(db, loginAttemptExists); err != nil {
		return err
	}

	if err := createRecoveryKeyRecords(db); err != nil {
		return err
	}

	if err := createAuditCheckpoints(db, auditCkptExists); err != nil {
		return err
	}

	if err := createConnectTables(db, connectRefGrantExists, connectorProjectBindingsExists); err != nil {
		return err
	}

	if err := createAccessRequestTables(db, invitationsExists, accessReqExists, accessReqApprovalsExists, rejectionReasonTemplateExists); err != nil {
		return err
	}

	if err := createAccessReviewCampaigns(db, campaignExists); err != nil {
		return err
	}

	if err := createBreakGlassActivations(db, breakGlassExists); err != nil {
		return err
	}

	if err := createLegalHolds(db, legalHoldExists); err != nil {
		return err
	}

	if err := createRiskExceptions(db, riskExceptionExists); err != nil {
		return err
	}

	if err := createSSOLoginStates(db, ssoLoginStateExists); err != nil {
		return err
	}

	if err := createSchedulerLockLeases(db, schedulerLockLeaseExists); err != nil {
		return err
	}

	if err := createSoDPolicies(db, sodExists); err != nil {
		return err
	}

	if err := createSecretDependencies(db, secretDepExists); err != nil {
		return err
	}

	if err := createSecretACLs(db, secretACLExists); err != nil {
		return err
	}

	if err := createSecretAccessSchedules(db, scheduleExists); err != nil {
		return err
	}

	if err := createPendingAuditEvents(db, pendingAuditExists); err != nil {
		return err
	}

	if err := createPasswordHistories(db, pwHistExists); err != nil {
		return err
	}

	if err := createMachineIdentities(db, exec, machineExists); err != nil {
		return err
	}

	if err := createMachineIdentityCredentials(db, exec, machineCredExists); err != nil {
		return err
	}
	if err := createMachineIdentityRoleTables(db, machineRoleExists, machineOIDCExists); err != nil {
		return err
	}

	if err := createProjectMemberships(db, membershipExists); err != nil {
		return err
	}

	if err := createSetupTokens(db, setupTokenExists); err != nil {
		return err
	}

	if err := createNotifications(db, notificationsExists); err != nil {
		return err
	}
	if err := createUnmigratedFeatureTables(db, secretTemplateExists, alertEscalationExists, secretVersionCommentExists, mfaStepupTokenExists, hygieneTrendExists, compliancePostureExists); err != nil {
		return err
	}

	// At most one unread rotation/expiry reminder may stand per (user, project) at a
	// time — closing the #488 TOCTOU: the admin-jobs HTTP trigger for these two jobs
	// runs with no lock at all (unlike the scheduled path, single-replica-gated via
	// WithSchedulerLock, ADR-039), so two concurrent runs can both pass the
	// check-then-act "does a reminder already exist" read before either commits its
	// insert. Close the race at the DB layer regardless of whether the table
	// pre-existed.
	if err := ensureReminderNotificationDedupIndex(db); err != nil {
		return err
	}

	if err := alterGroups(db, exec, groupsExists); err != nil {
		return err
	}

	if err := alterUserGroupsProjectID(db, exec); err != nil {
		return err
	}

	if err := alterUserIdentityIndexes(db, exec); err != nil {
		return err
	}

	if err := alterRoleAndSecretNodeNames(db, exec); err != nil {
		return err
	}

	if err := alterShareRecordIndex(db); err != nil {
		return err
	}

	if err := alterSecretVersionIndex(db); err != nil {
		return err
	}

	if err := alterProjectNameIndex(db, projectsExists); err != nil {
		return err
	}

	if err := createU1Tables(db, apiClientExists, apiTokenExists, apiCallLogExists, externalIdentityExists, grpcServiceExists, identityProviderExists, passwordResetExists, rateLimitExists, secretAccessLogExists, secretMetadataHistoryExists, settingExists); err != nil {
		return err
	}

	// freshInstallComplete is true only when EVERY model the transactional
	// block below migrates already has its table -- not just "projects"
	// present. A database left half-migrated by a crash BEFORE this and the
	// surrounding transaction (#2383) existed can have projects (and maybe
	// several more) but still be missing a later model's table; checking
	// projects alone (the original gate) would wrongly treat that database
	// as fully initialised forever, exactly the bug #2383's transaction
	// prevents going FORWARD but cannot retroactively repair for a database
	// that was already left in that state before the fix shipped.
	freshInstallComplete := projectsExists && environmentExists && userExists &&
		roleExists && permissionExists && rolePermissionExists && userRoleExists &&
		groupsExists && userGroupExists && groupRoleExists && secretNodeExists &&
		secretVersionExists && shareRecordExists && sessionExists && tagExists &&
		secretTagExists && auditEventExists && systemMetadataExists && anomalyAlertExists &&
		anomalyConfigRecordExists && statsSnapshotExists && deploymentStatsSnapshotExists &&
		mfaStepUpGrantExists
	if freshInstallComplete {
		// Gap 2 (ADR-097 conformance): this early return is taken on EVERY boot of
		// an already-initialized database -- which, after the very first boot, is
		// every boot there is. recordSchemaEpoch previously lived ONLY at the end
		// of the transactional fresh-install tail below, so an established
		// database's schema_epoch row was written once (at first install) and
		// never again -- a binary upgrade that bumps currentSchemaEpoch in the
		// future would never record the new value here, permanently freezing the
		// stored epoch and silently defeating checkSchemaEpoch's whole comparison
		// (a dbEpoch that can never advance can never be read as "too new" either).
		// Not a corruption risk by itself (checkSchemaEpoch already ran at the top
		// of this function and would have refused first), but recordSchemaEpoch
		// must run on this path too, as the last step, same invariant as the
		// transactional tail: only after every other step on this path (none,
		// here -- the additive-migration section above already ran) has succeeded.
		return recordSchemaEpoch(db)
	}
	// Everything from here to the end of the function applies atomically,
	// whether this is a genuinely fresh install (every flag above false) or a
	// database left half-migrated by a pre-#2383 crash (some flags true, some
	// false): AutoMigrate on a model whose table already exists is a safe,
	// idempotent no-op, so this transaction either performs a full fresh
	// install or FINISHES an interrupted one, never re-creating or
	// corrupting what already exists. The transaction itself still matters
	// going forward even with freshInstallComplete's broader check: without
	// it, each AutoMigrate/index/backfill call below would auto-commit
	// independently on SQLite, so a NEW crash partway through could leave
	// yet another half-migrated state for a future boot to detect and
	// finish -- correct, but needlessly repeating the same multi-boot dance
	// instead of completing in one shot. SQLite supports transactional DDL
	// (CREATE/ALTER TABLE, CREATE INDEX), so this is safe there; on Postgres
	// this nests as a savepoint inside withMigrationLock's already-
	// transactional wrapper (harmless, not required for correctness there,
	// since Postgres was already atomic end to end).
	return db.Transaction(func(tx *gorm.DB) error {
		// Fresh-install steps (a new or half-migrated database only; an initialised one
		// returned above). How to add a migration step: a new model goes in the AutoMigrate
		// list below and in freshInstallComplete above; any other step is appended before
		// recordSchemaEpoch, which stays last. A step an existing database also needs is
		// called from the lists above as well.
		// Migrated one model per AutoMigrate call, not as one bulk variadic call: on a
		// fresh Postgres, re-inspecting a table that AutoMigrate already created
		// earlier in this same run trips a pgx prepared-statement cache bug
		// ("insufficient arguments") on whichever query runs afterward — the same
		// hazard the Notification/RotationPolicy exclusions above already guard
		// against. Any model already migrated by a dedicated block above (e.g.
		// AuditCheckpoint, guarded by auditCkptExists) must NOT also appear in this
		// list, or its re-inspection here will corrupt the cache for later models.
		for _, m := range []any{
			&models.Project{},
			&models.Environment{},
			&models.User{},
			&models.Role{},
			&models.Permission{},
			&models.RolePermission{},
			&models.UserRole{},
			&models.Group{},
			&models.UserGroup{},
			&models.GroupRole{},
			&models.SecretNode{},
			&models.SecretVersion{},
			&models.ShareRecord{},
			&models.Session{},
			&models.Tag{},
			&models.SecretTag{},
			&models.AuditEvent{},
			// NOTE: AuditCheckpoint is intentionally NOT listed here — it is migrated
			// by the dedicated block above (guarded by auditCkptExists). Listing it
			// again re-inspects the just-created table and trips the pgx
			// "insufficient arguments" bug (same hazard as Notification/RotationPolicy).
			//
			// SESSION-U guard U1: SecretAccessLog, SecretMetadataHistory, PasswordReset,
			// Setting, APIClient, APIToken, RateLimit, APICallLog, GRPCService,
			// IdentityProvider and ExternalIdentity are likewise intentionally NOT listed
			// here any more — each is now migrated unconditionally by its own
			// existence-gated block above (apiClientExists et al.), so a database
			// upgrading from an older schema gets them too, not only a truly fresh
			// install. Re-listing any of them here would re-trip the same pgx hazard.
			&models.SystemMetadata{},
			&models.AnomalyAlert{},
			&models.AnomalyConfigRecord{},
			&models.StatsSnapshot{},
			&models.DeploymentStatsSnapshot{},
			// MFAStepUpGrant (store-mfa-002): was never migrated anywhere — a fresh
			// install's CreateMFAStepUpGrant/GetActiveMFAStepUpGrant/
			// PruneMFAStepUpGrants calls (VerifyMFAStepUp, the classification gate,
			// and the mfa_stepup_grant_prune maintenance sweep) would all fail with
			// "no such table" / "relation does not exist" against a real database.
			// A plain new, simple table with no legacy columns to conditionally
			// backfill, so it belongs in this generic bulk list rather than one of
			// the guarded/existence-checked blocks above (those exist for models
			// that need to distinguish "already existed" from "freshly created" to
			// decide whether to add a follow-up column).
			&models.MFAStepUpGrant{},
		} {
			if err := tx.AutoMigrate(m); err != nil {
				return fmt.Errorf("failed to migrate %T: %w", m, err)
			}
			migrationCheckpointHook(fmt.Sprintf("freshinstall:after:%T", m))
		}
		// The Group, User, and Project models carry no plain unique tag on
		// name/username/name; enforce uniqueness only among live rows via partial indexes
		// (so a soft-deleted name/username can be reused, e.g. on SCIM re-provisioning).
		if err := ensureGroupNameIndex(tx); err != nil {
			return err
		}
		if err := ensureUserNameIndex(tx); err != nil {
			return err
		}
		if err := ensureUserEmailIndex(tx); err != nil {
			return err
		}
		if err := ensureUserExternalIDIndex(tx); err != nil {
			return err
		}
		// ADR-025 account-state root-cause fix: backfill any blank/unset
		// account_state to an explicit "active" before adding the constraint
		// that refuses to let a NEW blank land -- see backfillBlankAccountState's
		// own doc for why this matters (AccountLoginBlocked treats blank the
		// same as active, silently reactivating a suspended/deprovisioned
		// account for login).
		if err := backfillBlankAccountState(tx); err != nil {
			return err
		}
		if err := guardAccountStateValid(tx); err != nil {
			return err
		}
		if err := ensureProjectNameIndex(tx); err != nil {
			return err
		}
		if err := ensureRoleNameIndex(tx); err != nil {
			return err
		}
		if err := ensureSecretNodeNameNFC(tx); err != nil {
			return err
		}
		// #STORAGE-FACTORY-MT006-FIRSTBOOT: unlike every sibling ensure*Index call in
		// this block, ensureSecretNodeNameIndex previously had only its EARLY,
		// tableExists-gated call site above (the "additive migration for existing
		// databases" section) — no safety-net call here. On a genuinely fresh
		// install, secret_nodes doesn't exist yet at that earlier point (it's
		// created by the bulk AutoMigrate loop above, same as every other model
		// this block's siblings cover), so the early call is always skipped and the
		// MT-006 partial unique index was never created on a first boot — only from
		// the SECOND migrateDatabase run onward (e.g. after the first restart).
		// Confirmed directly: one CreateStorage call against a fresh schema left
		// uniq_secret_nodes_project_env_name_active absent on both SQLite and
		// Postgres; a second call against the same schema created it. Between
		// first boot and first restart, core.CreateSecret's GetSecretByName
		// check-then-act TOCTOU (the exact race this index exists to close) had no
		// DB-level backstop at all. Added here, unconditionally, matching every
		// other ensure*Index call in this block — idempotent, so this is a no-op
		// on a DB that already has the index from an earlier run.
		if err := ensureSecretNodeNameIndex(tx); err != nil {
			return err
		}
		if err := ensureShareRecordUniqueIndex(tx); err != nil {
			return err
		}
		if err := ensureSecretVersionIndex(tx); err != nil {
			return err
		}
		// Runs here, in the final block, rather than in the early
		// additive-migration section: this block is reached on BOTH a fresh
		// install and an upgrade (the old `if projectsExists { return nil }` gate
		// is long gone), and being after the bulk AutoMigrate loop it cannot
		// trip the pgx "insufficient arguments" hazard that re-inspecting a
		// just-ALTERed table causes (see automigrate_altered_table_hazard_test.go
		// and the AutoMigrate list's own NOTEs). The cache_epoch COLUMN is a
		// field on models.SecretNode so the bulk AutoMigrate loop above already
		// created it; the TRIGGER that maintains it is not something AutoMigrate
		// can create, and this is the ONLY thing that does — on every path.
		// Defined in package store (store.EnsureSecretNodeCacheEpoch), not here,
		// so the cache's own tests (which live in that package) build their
		// schema with the same call rather than a second copy of the SQL that
		// could drift — and so they fail loudly instead of running against a
		// trigger-less schema, i.e. a stamp that never moves, passing vacuously.
		if err := store.EnsureSecretNodeCacheEpoch(tx); err != nil {
			return err
		}
		// DEK-SWEEP-CACHE-1: no-op when AutoMigrate already created the column from
		// models.SecretVersion; covers a half-migrated install.
		if err := store.EnsureSecretVersionCacheEpoch(tx); err != nil {
			return err
		}
		// #3259: the role->permission cache generation triggers (fresh-install
		// call site; see the upgrade one above).
		if err := store.EnsureRolePermissionsGenerationTriggers(tx); err != nil {
			return err
		}
		// #3362: the suspend-marker trigger (fresh-install call site).
		if err := store.EnsureSecretSuspendMarkerTrigger(tx); err != nil {
			return err
		}
		// #3359: the retention-anchor layout trigger (fresh-install call site).
		if err := store.EnsureAuditRetentionAnchorTrigger(tx); err != nil {
			return err
		}
		// ADR-097: only after every migration step above has succeeded -- a crash
		// or error partway through must not advance the recorded epoch past what
		// was actually, successfully applied.
		return recordSchemaEpoch(tx)
	})
}

// ensureRoleNameIndex replaces Role.Name's original plain `unique` gorm tag
// (which only caught byte-identical duplicates) with a partial-free (roles
// carry no soft-delete) unique index on name_folded — identity.NewFoldedName's
// NFC+case-fold output, #1642 — so "Admin"/"admin" can't coexist as two
// indistinguishable roles in an access review. Idempotent; works on both
// SQLite and Postgres.
// dropLegacyGormUniqueTagArtifact removes the uniqueness artifact GORM's plain
// `unique` struct tag left behind, whichever form the dialect gave it.
//
// This distinction is the whole reason the function exists. On SQLite -- the
// dev and test backend, and therefore the only one CI ever migrates -- a
// `unique` tag produces a plain index, and DROP INDEX removes it. On Postgres
// it produces a UNIQUE CONSTRAINT that *owns* an index of the same name, and
// Postgres refuses to drop that index directly:
//
//	ERROR: cannot drop index uni_roles_name because constraint uni_roles_name
//	on table roles requires it (SQLSTATE 2BP01)
//
// which aborted migrateDatabase and stopped the server booting. Found on the
// DAST rig's real Postgres volume, 2026-09-11, immediately behind the missing
// folded columns -- the second Postgres-only, upgrade-only defect in the same
// migration, both invisible to a SQLite test suite.
//
// Constraint first, then index: DROP CONSTRAINT removes the owned index with
// it, so the DROP INDEX that follows is a no-op on Postgres and does the real
// work on SQLite. Both are IF EXISTS, so this is idempotent either way. The
// table and constraint names are passed as whole literal statements by the
// callers rather than built here, keeping the no-runtime-built-identifier
// discipline the surrounding code follows deliberately.
func dropLegacyUniqueConstraint(db *gorm.DB, alterStmt string) error {
	if db.Dialector.Name() != "postgres" {
		return nil
	}
	if err := db.Exec(alterStmt).Error; err != nil {
		return fmt.Errorf("migration failed (%s): %w", alterStmt, err)
	}
	return nil
}

func ensureRoleNameIndex(db *gorm.DB) error {
	// Drop the unique constraint/index GORM's original `unique` tag on Name
	// created. GORM names a plain `unique` tag's index uni_<table>_<column>.
	// On Postgres that name belongs to a CONSTRAINT, which DROP INDEX alone
	// cannot remove -- see dropLegacyUniqueConstraint above.
	if err := dropLegacyUniqueConstraint(db, "ALTER TABLE roles DROP CONSTRAINT IF EXISTS uni_roles_name"); err != nil {
		return err
	}
	if err := db.Exec("DROP INDEX IF EXISTS uni_roles_name").Error; err != nil {
		return fmt.Errorf("failed to drop legacy roles name index: %w", err)
	}
	if err := backfillFoldedColumn(db, "roles", "id", "name", "name_folded", "", foldIdentity); err != nil {
		return err
	}
	const idxName = "uniq_roles_name_folded"
	// #490: other tables (RolePermission, UserRole, GroupRole) reference a
	// role by ID, so auto-deleting one of two "duplicate name" roles would
	// silently orphan any real permission grants tied to the deleted role's
	// ID. Fail loud instead so an operator resolves the collision
	// deliberately.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "roles", "name_folded", "",
			"rename or delete one of the conflicting roles via the application's role API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON roles (name_folded)").Error; err != nil {
		return fmt.Errorf("failed to create roles name_folded index: %w", err)
	}
	return nil
}

// ensureSecretNodeNameNFC NFC-normalizes any pre-existing secret_nodes.name
// value that isn't already in NFC form (#1642). Unlike the *_folded columns
// elsewhere in this file, secret names are addresses, not human-verified
// identity — they are NOT case-folded (PROD_KEY and prod_key must remain
// distinct) — so there is no separate column: uniq_secret_nodes_project_env_name_active
// (ensureSecretNodeNameIndex, already byte-exact/case-sensitive on both
// backends) stays exactly as it is; this only ensures the name column itself
// never holds two different Unicode representations of what a human reads as
// the same address.
func ensureSecretNodeNameNFC(db *gorm.DB) error {
	// Scoped by (project_id, environment_id): secret_nodes.name is only
	// unique WITHIN that scope (uniq_secret_nodes_project_env_name_active),
	// not globally -- two secrets legitimately named "DATABASE_URL" in two
	// different projects are not a collision. Passing this unscoped would
	// make normalizeColumnInPlace group by name alone and falsely refuse to
	// migrate any installation with the same secret name reused across
	// projects, an extremely common pattern.
	return normalizeColumnInPlace(db, "secret_nodes", "id", "name", sqlWhereNotDeleted, "project_id, environment_id", normalizeAddress)
}

// ensureShareRecordUniqueIndex creates a partial unique index on share_records
// (secret_id, recipient_id, is_group), scoped to live rows (#136). ShareRecord
// carried no DB constraint preventing two active share rows for the same
// (secret, recipient, is_group) tuple: CreateShareRecord's check-then-create is a
// read-then-write race, and a revoke-by-ID only ever removed one of the resulting
// duplicates, leaving access live after what looked like a successful single-share
// revoke. Idempotent; works on SQLite and Postgres.
func ensureShareRecordUniqueIndex(db *gorm.DB) error {
	const idxName = "uniq_share_records_active"
	// #490: two colliding share rows can carry different Permission ("read" vs
	// "write") or ExpiresAt values — an auto-delete keyed on lowest-id could
	// silently discard the intended grant and leave the wrong one (e.g. a
	// stale broader "write" share) in effect. Fail loud instead so an operator
	// resolves the conflict deliberately.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "share_records", "secret_id, recipient_id, is_group", sqlWhereNotDeleted,
			"revoke or re-share the conflicting active share record(s) for the affected secret+recipient via the application's share revoke/create API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON share_records (secret_id, recipient_id, is_group) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial share_records unique index: %w", err)
	}
	return nil
}

// ensureSecretNodeNameIndex creates a partial unique index on secret_nodes
// (project_id, environment_id, name) WHERE deleted_at IS NULL, enforcing at the
// DB layer the uniqueness the application already assumes in GetSecretByName.
// Partial (deleted_at IS NULL) so a soft-deleted secret's name is freed for reuse,
// matching the same soft-delete contract used for users, groups, and projects.
// This closes the MT-006 TOCTOU in core.CreateSecret (GetSecretByName check-then-act).
// Idempotent; works on SQLite and Postgres.
func ensureSecretNodeNameIndex(db *gorm.DB) error {
	const idxName = "uniq_secret_nodes_project_env_name_active"
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "secret_nodes", "project_id, environment_id, name", sqlWhereNotDeleted,
			"rename or delete one of the conflicting secrets via the application's secret API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON secret_nodes (project_id, environment_id, name) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create secret_nodes unique-name index: %w", err)
	}
	return nil
}

// ensureSecretVersionIndex creates a unique index on secret_versions
// (secret_node_id, version_number) closing the #121 TOCTOU: RotateSecret's
// GetLatestSecretVersion -> +1 -> storeSecretVersion sequence is a read-then-write
// race, empirically reproduced (100% of runs, 15 concurrent rotations) producing
// multiple rows sharing one version_number under the same secret_id. Idempotent;
// works on SQLite and Postgres.
func ensureSecretVersionIndex(db *gorm.DB) error {
	const idxName = "uniq_secret_versions_node_version"
	// #490: two rows colliding on version_number came from the exact
	// concurrent-rotation race this index closes — they very plausibly hold
	// two DIFFERENT EncryptedValue payloads. GetLatestSecretVersion resolves
	// the "current" version by `ORDER BY version_number DESC LIMIT 1`
	// (store/local_secrets.go), which is an undefined tie-break across a
	// version_number collision; auto-deleting the lowest-id row could
	// silently discard the actual most-recently-rotated secret value and roll
	// the vault back to stale content with zero signal. There is no
	// application-level "merge two secret versions" API, so this fails loud
	// and points at a manual, out-of-band resolution instead.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "secret_versions", "secret_node_id, version_number", "",
			"resolve the conflicting secret version rows manually (they may hold different encrypted values from a version-number race) — consult the operator runbook or contact support before upgrading; do not delete either row without first confirming which encrypted value is current"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON secret_versions (secret_node_id, version_number)").Error; err != nil {
		return fmt.Errorf("failed to create secret_versions unique index: %w", err)
	}
	return nil
}

// ensureDynamicSecretConfigNameIndex creates a unique index on
// dynamic_secret_configs (project_id, environment_id, name), matching
// DynamicSecretConfig's doc comment ("one per (project, env, name)", #462).
// DynamicSecretConfig has no soft-delete column, so — unlike the partial indexes
// above — this is a plain (non-partial) unique index. Idempotent; works on SQLite
// and Postgres.
func ensureDynamicSecretConfigNameIndex(db *gorm.DB) error {
	const idxName = "uniq_dynamic_secret_configs_project_env_name"
	// #490: a pre-existing install that accumulated duplicate (project, env,
	// name) rows before this index shipped — via the same check-then-create
	// race the index closes, a bulk import, or a restore — would otherwise
	// hit a bare CREATE UNIQUE INDEX failure here, propagating out of
	// migrateDatabase and blocking the server from starting at all on upgrade.
	// Two colliding rows can carry different AdminDSNEnc/CreationTemplate/
	// BackendType values, so this fails loud instead of auto-deleting one and
	// silently breaking whichever lease depended on its specific connection
	// details.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "dynamic_secret_configs", "project_id, environment_id, name", "",
			"rename or delete one of the conflicting dynamic secret configs via the application's dynamic-secret-config API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON dynamic_secret_configs (project_id, environment_id, name)").Error; err != nil {
		return fmt.Errorf("failed to create dynamic_secret_configs unique index: %w", err)
	}
	return nil
}

// ensureGroupNameIndex replaces any plain unique index on groups.name with a
// partial unique index on name_folded (identity.NewFoldedName's NFC+case-fold
// output, #1642), scoped to non-deleted rows so a soft-deleted group's name is
// freed for reuse while the group stays restorable. Idempotent; works on both
// SQLite and Postgres (both support partial indexes and IF [NOT] EXISTS).
func ensureGroupNameIndex(db *gorm.DB) error {
	// Drop the legacy plain unique index from the old `unique` tag, and the
	// raw-name (exact-match, pre-#1642) partial index this replaces. Unrolled
	// into individual literal statements (no runtime-built identifier) rather
	// than looping over a slice, so this can't even shape-match a
	// string-formatted-query finding.
	if err := dropLegacyUniqueConstraint(db, "ALTER TABLE groups DROP CONSTRAINT IF EXISTS uni_groups_name"); err != nil {
		return err
	}
	if err := db.Exec("DROP INDEX IF EXISTS uni_groups_name").Error; err != nil {
		return fmt.Errorf("failed to drop legacy groups name index %q: %w", "uni_groups_name", err)
	}
	if err := db.Exec("DROP INDEX IF EXISTS uniq_groups_name_active").Error; err != nil {
		return fmt.Errorf("failed to drop legacy groups name index %q: %w", "uniq_groups_name_active", err)
	}
	// name_folded is Name run through identity.NewFoldedName — see
	// models.Group.NameFolded's doc comment. Backfilling happens before the
	// new index so any pre-existing row a normalization-aware write path
	// never touched still gets one.
	if err := backfillFoldedColumn(db, "groups", "id", "name", "name_folded", sqlWhereNotDeleted, foldIdentity); err != nil {
		return err
	}
	const idxName = "uniq_groups_name_folded_active"
	// #490: other tables (GroupRole, UserGroup) reference a group by ID, so
	// auto-deleting one of two "duplicate name" groups would silently orphan
	// any real memberships/role-grants tied to the deleted group's ID. Fail
	// loud instead so an operator resolves the name collision deliberately.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "groups", "name_folded", sqlWhereNotDeleted,
			"rename or delete one of the conflicting groups via the application's group-rename/delete API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON groups (name_folded) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial groups name_folded index: %w", err)
	}
	return nil
}

// ensureProjectMembershipIndex creates a partial unique index enforcing at most one
// non-revoked ProjectMembership per (project, user) at the DB layer. InviteMember's
// own check-then-create ("one active onboarding per (project, user)") is a TOCTOU:
// two concurrent invites for the same pair can both pass the "no active membership"
// read before either commits its Create, producing two non-revoked rows (#309). The
// index makes the second concurrent Create fail with a constraint violation instead,
// which CreateProjectMembership/InviteMember translate into the same clean
// "already has a membership" error a sequential caller would get. Idempotent; mirrors
// ensureGroupNameIndex/ensureUserNameIndex (partial unique index, live rows only).
func ensureProjectMembershipIndex(db *gorm.DB) error {
	const idxName = "uniq_project_memberships_active"
	// #490: the #309 race this index closes lets two concurrent invites for
	// the same (project, user) both commit — plausibly with different Role
	// values. Auto-deleting the lowest-id row doesn't necessarily keep the
	// intended/correct role, so this fails loud instead.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "project_memberships", "project_id, user_id", "state <> 'revoked'",
			"revoke one of the conflicting non-revoked memberships for the affected project+user via the application's membership-revoke API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName +
		" ON project_memberships (project_id, user_id) WHERE state <> 'revoked'").Error; err != nil {
		return fmt.Errorf("failed to create partial project_memberships index: %w", err)
	}
	return nil
}

// ensureBreakGlassActiveIndex creates a partial unique index on
// break_glass_activations (project_id, user_id) WHERE state='active', so at most one
// ACTIVE break-glass activation can exist per project+user even under a race —
// ActivateBreakGlass's own "no existing active activation" check is a list-and-scan
// that two concurrent callers could both pass before either inserts; this index makes
// the database the actual source of truth. Scoped to state='active' (not a plain
// unique index) so a user can activate break-glass again after a prior activation
// expires or is revoked. Idempotent; works on both SQLite and Postgres.
func ensureBreakGlassActiveIndex(db *gorm.DB) error {
	const idxName = "uniq_break_glass_active_project_user"
	// #490: an "extra" active break-glass row here is not an incidental
	// duplicate of the same event — it is a distinct, audit-relevant
	// activation record. Silently deleting or re-statusing one at boot would
	// itself be a consequential, compliance-sensitive action, so this
	// deliberately does NOT auto-remediate; it just fails with an actionable
	// message (instead of an opaque DB constraint error) telling the operator
	// to resolve the conflict via the application's own revoke API first,
	// which records a proper audit entry.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "break_glass_activations", "project_id, user_id", "state = 'active'",
			"revoke the extra active break-glass activation(s) for the affected project+user via the application's break-glass revoke API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON break_glass_activations (project_id, user_id) WHERE state = 'active'").Error; err != nil {
		return fmt.Errorf("failed to create partial break_glass_activations active index: %w", err)
	}
	return nil
}

// ensureUserNameIndex replaces the plain unique index on users.username (from the old
// `uniqueIndex` tag) with a partial unique index scoped to non-deleted rows. Without
// this a SCIM-deprovisioned (soft-deleted) user keeps occupying the username in the
// unique index, so re-provisioning the same userName collides on INSERT and the IdP's
// provisioning run errors indefinitely. Idempotent; works on SQLite and Postgres.
func ensureUserNameIndex(db *gorm.DB) error {
	// Drop the legacy plain unique index. GORM's `uniqueIndex` tag names it
	// idx_users_username; the older `unique` tag would be uni_users_username. Drop
	// all three. Unrolled into individual literal statements (no runtime-built
	// identifier) rather than looping over a slice, so this can't even
	// shape-match a string-formatted-query finding.
	if err := db.Exec("DROP INDEX IF EXISTS idx_users_username").Error; err != nil {
		return fmt.Errorf("failed to drop legacy users username index %q: %w", "idx_users_username", err)
	}
	if err := dropLegacyUniqueConstraint(db, "ALTER TABLE users DROP CONSTRAINT IF EXISTS uni_users_username"); err != nil {
		return err
	}
	if err := db.Exec("DROP INDEX IF EXISTS uni_users_username").Error; err != nil {
		return fmt.Errorf("failed to drop legacy users username index %q: %w", "uni_users_username", err)
	}
	if err := db.Exec("DROP INDEX IF EXISTS uniq_users_username_active").Error; err != nil {
		return fmt.Errorf("failed to drop legacy users username index %q: %w", "uniq_users_username_active", err)
	}
	// #1642: username_folded is Username run through identity.NewFoldedName
	// (NFC-normalized AND case-folded) — see models.User.UsernameFolded's doc
	// comment. Backfilling happens before the new index so any pre-existing
	// row a normalization-aware write path never touched still gets one.
	// Precis-based folding can't be expressed as a portable SQL expression
	// (unlike the old raw-username index this replaces), so this is a Go-side
	// backfill (normalize_backfill.go), not a SQL migration.
	if err := backfillFoldedColumn(db, "users", "id", "username", "username_folded", sqlWhereNotDeleted, foldIdentity); err != nil {
		return err
	}
	const idxName = "uniq_users_username_folded_active"
	// #490: two accounts colliding on username are two DIFFERENT real users
	// (their own PasswordHash, MFA config, sessions), and other tables
	// (roles, audit logs, owned secrets, sessions) reference a user by ID —
	// auto-deleting one would silently delete a real account/credential and
	// leave those references dangling. Fail loud instead. In practice this
	// duplicates backfillFoldedColumn's own collision refusal above, but is
	// kept as defense in depth for a row written directly to the DB outside
	// any Go write path (e.g. a manual restore) with a pre-populated,
	// colliding username_folded value.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "users", "username_folded", sqlWhereNotDeleted,
			"merge or rename the conflicting user accounts via the application's admin user API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON users (username_folded) WHERE deleted_at IS NULL").Error; err != nil {
		return fmt.Errorf("failed to create partial users username_folded index: %w", err)
	}
	return nil
}

// ensureUserEmailIndex creates a partial, case-insensitive unique index on
// users.email_folded, scoped to live (non-deleted) rows with a non-empty
// email (#117). Without a DB-level constraint, email uniqueness was enforced
// only by a check-then-act read (GetUserByEmail) before each create/update,
// which is racy: two concurrent CreateUser/signup/invite-accept/SCIM-provision
// calls for the identical email could both pass their pre-check before either
// write landed, producing multiple rows sharing one email that GetUserByEmail
// then resolves to an arbitrary one of — an ambiguous login/identity-resolution
// bug, empirically reproduced at a 100% rate under concurrency. The index is
// on email_folded (identity.NewFoldedName's NFC+case-fold output), not a raw
// SQL LOWER(email) expression (#1642): LOWER() folds ASCII-only on SQLite (no
// ICU) but locale-dependent on Postgres, so the exact same login-identity
// column enforced different uniqueness on different backends. Scoped to
// `deleted_at IS NULL` so a soft-deleted (e.g. SCIM-deprovisioned) user's email
// is freed for reuse on re-provisioning, mirroring ensureUserNameIndex; `email
// <> ”` so any legacy rows with no email recorded don't collide with each
// other. Idempotent; works on both SQLite and Postgres.
func ensureUserEmailIndex(db *gorm.DB) error {
	// Drop the previous LOWER(email)-expression index this replaces (#1642 —
	// see models.User.EmailFolded's doc comment for why SQL-side LOWER() was
	// backend-divergent).
	if err := db.Exec("DROP INDEX IF EXISTS uniq_users_email_active").Error; err != nil {
		return fmt.Errorf("failed to drop legacy users email index: %w", err)
	}
	// email_folded is Email run through identity.NewFoldedName, backfilled
	// only for non-empty emails — an empty EmailFolded is fine and expected
	// for the legacy/machine rows the index below already excludes.
	if err := backfillFoldedColumn(db, "users", "id", "email", "email_folded", "deleted_at IS NULL AND email <> ''", foldIdentity); err != nil {
		return err
	}
	const idxName = "uniq_users_email_folded_active"
	// #490: same reasoning as ensureUserNameIndex — two accounts colliding on
	// email are two DIFFERENT real accounts with their own credential/MFA
	// state, and other tables reference a user by ID. Fail loud instead of
	// auto-deleting one.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "users", "email_folded", "deleted_at IS NULL AND email <> ''",
			"merge or update the email of one of the conflicting user accounts via the application's admin user API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON users (email_folded) WHERE deleted_at IS NULL AND email <> ''").Error; err != nil {
		return fmt.Errorf("failed to create partial users email_folded index: %w", err)
	}
	return nil
}

// ensureUserExternalIDIndex creates a partial unique index on users.external_id,
// scoped to live rows with a non-empty external_id (#117). external_id (the
// SCIM/IdP-asserted identifier) was indexed but NOT unique, explicitly
// documented as allowing "legacy/blank rows [to] coexist" — but two DIFFERENT
// users sharing the same non-empty external_id is exactly the ambiguity SSO/
// SCIM identity resolution (GetUserByExternalID) must not tolerate: which one
// does a federated login authenticate as? Empty external_id (every locally-
// created account) is excluded so native users never collide with each other.
// Idempotent; works on SQLite and Postgres.
func ensureUserExternalIDIndex(db *gorm.DB) error {
	const idxName = "uniq_users_external_id_active"
	// #490: same reasoning as ensureUserNameIndex/ensureUserEmailIndex — two
	// accounts colliding on external_id are two DIFFERENT real accounts.
	// Deciding which is the authoritative SSO/SCIM identity is a deliberate
	// admin call, not something an unattended migration should guess by
	// lowest-id. Fail loud instead.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "users", "external_id", "deleted_at IS NULL AND external_id != ''",
			"resolve the conflicting user accounts sharing this external_id (rename/merge/deprovision one) via the application's admin user API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON users (external_id) WHERE deleted_at IS NULL AND external_id != ''").Error; err != nil {
		return fmt.Errorf("failed to create partial users external_id index: %w", err)
	}
	return nil
}

// ensureProjectNameIndex creates a partial, case-insensitive unique index on
// projects.name scoped to live (non-deleted) rows with a non-empty name (#385).
// Project.Name previously carried only a plain, case-sensitive `uniqueIndex` tag, so
// "Production"/"production" (and any other case variant) were distinct, both-succeeding
// rows — and the CLI's project name resolution (resolveProjectID, import.go) resolves by
// case-insensitive comparison over an unordered project list, returning the FIRST match.
// A secrets.write holder could therefore plant a same-name-different-case shadow project
// the old index didn't block, and a later `keyorix secret import/export --project
// production` could silently resolve against the shadow project instead of the intended
// one. The index is on LOWER(name) so it catches every case variant, mirroring
// ensureUserEmailIndex's treatment of users.email (#117) for the identical
// shadow-identity class of bug. Scoped to `deleted_at IS NULL` so a soft-deleted
// project's name is freed for reuse on re-creation, mirroring ensureGroupNameIndex/
// ensureUserNameIndex; `name <> ”` so any legacy rows with no name recorded don't
// collide with each other. Idempotent; works on both SQLite and Postgres.
//
// Known residual limitation: this closes the case-folding gap but not the
// Unicode-homoglyph one — "Prοduction" (Greek omicron, U+03BF) still normalizes to a
// distinct LOWER() value from "production" and would still create a separate row. Full
// NFKC normalization plus homoglyph/confusable detection is a materially harder problem
// (Unicode Technical Standard #39) and is intentionally out of scope here.
func ensureProjectNameIndex(db *gorm.DB) error {
	const idxName = "uniq_projects_name_active"
	// #490: this index is ADDING name uniqueness for the first time — nothing
	// enforced it before, so on a pre-existing install two DIFFERENT,
	// legitimate projects could plausibly share a display name coincidentally.
	// Projects are the parent of secrets/environments/machine identities via
	// project_id foreign keys that this migration does not cascade-delete;
	// auto-removing one "duplicate" project would silently orphan an entire
	// project's worth of child data. Fail loud instead.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "projects", "LOWER(name)", "deleted_at IS NULL AND name <> ''",
			"rename or archive one of the conflicting projects via the application's project-rename/archive API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON projects (LOWER(name)) WHERE deleted_at IS NULL AND name <> ''").Error; err != nil {
		return fmt.Errorf("failed to create partial projects name index: %w", err)
	}
	return nil
}

// ensureLegalHoldActiveIndex creates a partial unique index that permits at most one
// un-released (released = false) row in legal_holds at a time, closing the
// place-hold TOCTOU race (#305): since every row matching the predicate shares the
// same released=false value, uniqueness on that column caps the table at one such
// row, and a second concurrent INSERT is rejected by the DB instead of silently
// creating an orphaned duplicate hold. Idempotent; works on both SQLite and Postgres
// (both support partial indexes and IF NOT EXISTS).
func ensureLegalHoldActiveIndex(db *gorm.DB) error {
	const idxName = "uniq_legal_holds_active"
	// #490: same reasoning as ensureBreakGlassActiveIndex — an un-released legal
	// hold is a compliance-relevant record, not an incidental duplicate. Auto-
	// deleting or auto-releasing one at boot would itself be a consequential,
	// audit-relevant action, so this deliberately does not auto-remediate; it
	// fails with an actionable message pointing at the application's own
	// release-hold API (which records a proper audit entry) instead of an
	// opaque DB constraint-violation error.
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "legal_holds", "released", "released = false",
			"release the extra active legal hold(s) via the application's legal-hold release API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " ON legal_holds (released) WHERE released = false").Error; err != nil {
		return fmt.Errorf("failed to create partial legal_holds active index: %w", err)
	}
	return nil
}

// ensureReminderNotificationDedupIndex creates a partial unique index that permits
// at most one unread rotation-reminder or expiry-reminder notification per
// (user_id, type, project_id) at a time (#488). SendRotationReminders and
// SendExpiryReminders each dedupe with a check-then-act read (an existing unread
// reminder for the user/project is not re-notified) followed by a separate
// CreateNotification call — a TOCTOU race. The scheduled path is safe (run under
// WithSchedulerLock, single-replica-gated, ADR-039), but the on-demand admin-jobs
// HTTP trigger (POST /api/v1/admin/jobs/rotation-reminders or .../expiry-reminders)
// calls the core function directly with no lock at all, so two concurrent runs — or
// one racing the scheduler's own tick — against a project with no existing reminder
// can both pass the "does a reminder already exist" check before either commits,
// producing duplicate reminder rows.
//
// Scoped to just these two notification types (via the type IN (...) predicate) —
// unlike rotation.reminder/secret.expiry_reminder, most other notification types
// (e.g. secret.shared) legitimately create more than one unread notification of the
// same type for the same user/project (one per distinct secret/event), so a
// blanket index across the whole table would silently drop those. Idempotent; works
// on both SQLite and Postgres (both support partial indexes and IF NOT EXISTS).
//
// Like every other ensure*Index helper in this file, this gates the CREATE UNIQUE
// INDEX on a pre-flight warnIfDuplicatesExist scan (#490, #STORAGE-FACTORY-004):
// an upgraded install that already accumulated colliding unread reminder rows
// before this index existed (e.g. via the very TOCTOU this index closes) would
// otherwise hit an opaque driver-level constraint-violation error deep inside
// migrateDatabase instead of a clear, actionable one. This was previously the one
// exception among this file's ensure*Index helpers that skipped the check.
func ensureReminderNotificationDedupIndex(db *gorm.DB) error {
	const idxName = "uniq_notifications_unread_reminder"
	if !indexExists(db, idxName) {
		if err := warnIfDuplicatesExist(db, "notifications", "user_id, type, project_id",
			"is_read = false AND type IN ('rotation.reminder', 'secret.expiry_reminder')",
			"mark one of the conflicting unread reminder notifications as read via the application's notifications API before upgrading"); err != nil {
			return err
		}
	}
	if err := db.Exec(sqlCreateUniqueIdx + idxName + " " +
		"ON notifications (user_id, type, project_id) " +
		"WHERE is_read = false AND type IN ('rotation.reminder', 'secret.expiry_reminder')").Error; err != nil {
		return fmt.Errorf("failed to create partial notifications reminder-dedup index: %w", err)
	}
	return nil
}
