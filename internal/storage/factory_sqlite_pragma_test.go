package storage

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/stretchr/testify/require"
)

// TestSQLitePragmas_EnabledOnFreshConnection pins #436/#465: the default
// local-storage (SQLite) backend must open every connection with foreign-key
// CONSTRAINT enforcement on, a non-zero busy_timeout, and WAL journal mode —
// none of which SQLite enables by default. Goes through the REAL production
// path (CreateStorage, the same call startHTTPServer/startGRPCServer make)
// against a temp-FILE-backed database, not ":memory:" (some pragmas, notably
// journal_mode=WAL, behave differently or are silently downgraded to a
// rollback journal for an in-memory database, so a ":memory:" connection
// would not actually exercise the fix).
func TestSQLitePragmas_EnabledOnFreshConnection(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "pragma-check.db")

	_, err := NewStorageFactory().CreateStorage(cfg)
	require.NoError(t, err)

	// Inspect the pragmas via a second, independent connection opened through
	// the same production helper (OpenGormDB) used by the CLI admin commands —
	// proving the pragmas are a property of every connection this codebase
	// opens against the configured path, not a one-off applied only inside
	// CreateStorage.
	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	var foreignKeys int
	require.NoError(t, sqlDB.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys))
	require.Equal(t, 1, foreignKeys, "foreign_keys pragma must be ON (#436)")

	var busyTimeoutMs int
	require.NoError(t, sqlDB.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeoutMs))
	require.GreaterOrEqual(t, busyTimeoutMs, 1000,
		"busy_timeout must be a real, non-trivial value so concurrent writers retry instead of failing immediately (#465)")

	var journalMode string
	require.NoError(t, sqlDB.QueryRow("PRAGMA journal_mode").Scan(&journalMode))
	require.Equal(t, "wal", journalMode, "journal_mode must be WAL so readers and a writer don't block each other (#465)")
}

// TestSQLiteForeignKeyEnforcement_RejectsOrphanInsert proves the #436 fix has
// real teeth: with foreign_keys=1 active, SQLite itself — not just application
// code — rejects an INSERT whose foreign key references a non-existent parent
// row, where before this fix (foreign_keys defaulting OFF) the identical
// INSERT would have silently succeeded and orphaned the row.
//
// NOTE ON SCOPE: this codebase's actual runtime schema is generated entirely
// by GORM AutoMigrate from the model structs in internal/storage/models, none
// of which currently declare a GORM-level "belongs to" association (they use
// plain e.g. `SecretNodeID uint` columns with no corresponding association
// field) — so AutoMigrate does not emit any FOREIGN KEY clause into the
// CREATE TABLE statements today, on SQLite OR Postgres. The `REFERENCES ...
// ON DELETE CASCADE` clauses in migrations/*.sql describe an intended schema
// but that file is never loaded/executed by this codebase (confirmed: no
// reference to it in any .go file), so they are not actually in effect. This
// test therefore declares its own minimal, explicit FK constraint (the only
// way SQLite supports one — it must be present at CREATE TABLE time and
// cannot be retrofitted via ALTER TABLE) over a connection opened through this
// package's real production code path, to prove the pragma the #436 fix
// enables is genuinely wired up and enforced by SQLite on every connection
// this codebase opens. Actually wiring real FK constraints into the
// AutoMigrate-generated model schema (which would additionally require a
// full-table-rebuild migration strategy for existing SQLite databases, since
// SQLite cannot ALTER TABLE ADD CONSTRAINT) is a materially larger, separate
// piece of schema work and intentionally out of scope here.
func TestSQLiteForeignKeyEnforcement_RejectsOrphanInsert(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Database.Path = filepath.Join(t.TempDir(), "fk-enforcement.db")

	db, err := OpenGormDB(cfg)
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	require.NoError(t, db.Exec(`CREATE TABLE fk_parent (id INTEGER PRIMARY KEY)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE fk_child (
		id INTEGER PRIMARY KEY,
		parent_id INTEGER NOT NULL REFERENCES fk_parent(id) ON DELETE CASCADE
	)`).Error)

	require.NoError(t, db.Exec(`INSERT INTO fk_parent (id) VALUES (1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO fk_child (id, parent_id) VALUES (1, 1)`).Error,
		"a child row referencing an existing parent must still succeed")

	err = db.Exec(`INSERT INTO fk_child (id, parent_id) VALUES (2, 999)`).Error
	require.Error(t, err, "a child row referencing a NON-existent parent must now be rejected by SQLite (#436), not silently orphaned")
	require.Contains(t, err.Error(), "FOREIGN KEY constraint failed")

	// The declared ON DELETE CASCADE also gets enforced now: deleting the
	// parent removes the dependent child row instead of orphaning it.
	require.NoError(t, db.Exec(`DELETE FROM fk_parent WHERE id = 1`).Error)
	var remaining int64
	require.NoError(t, db.Raw(`SELECT COUNT(*) FROM fk_child WHERE id = 1`).Scan(&remaining).Error)
	require.Equal(t, int64(0), remaining, "ON DELETE CASCADE must actually cascade now that foreign_keys enforcement is on")
}
