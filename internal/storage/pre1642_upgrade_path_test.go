// pre1642_upgrade_path_test.go — regression test for the upgrade path, which
// nothing else in this repository exercises.
//
// Every other migration test in this package starts from an empty database, so
// AutoMigrate creates every column from the model structs and the ordering
// inside migrateDatabase can never matter. The real upgrade -- new code against
// a database an older version created -- takes a different path entirely:
// migrateDatabase returns early once `projects` exists, AutoMigrate never runs,
// and any column added since that database was built has to be added by an
// explicit ADD COLUMN step on the existing-DB path.
//
// Three columns from #1642 did not have one. The result was not a degraded
// feature, it was a server that could not boot:
//
//	failed to migrate database: failed to read groups for name_folded backfill:
//	ERROR: column "name_folded" does not exist (SQLSTATE 42703)
//
// found by running v0.92.0 against a real PostgreSQL volume created around
// #1297, and reachable by any operator upgrading across that range.
//
// KNOWN BOUNDARY, stated rather than implied: this test runs on SQLite, so it
// covers the missing-column defect (dialect-independent -- the early return
// happens on both) and does NOT cover the second defect found in the same
// migration, where GORM's `unique` tag leaves a UNIQUE CONSTRAINT on Postgres
// but a plain index on SQLite, so DROP INDEX alone cannot remove it. That one
// is invisible to any SQLite test by construction and needs a Postgres-backed
// migration test to catch. Do not read a green run here as "the upgrade path
// is covered" -- read it as "the column half of it is".
package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// preFoldedSchema is the shape of a database created before #1642 introduced
// the folded-name columns: a `projects` table (which is what puts
// migrateDatabase on the existing-DB path at all), and groups/users carrying
// their pre-#1642 columns and nothing more. Deliberately hand-written rather
// than generated from the models, since generating it from today's structs
// would recreate exactly the columns whose absence is the thing under test.
var preFoldedSchema = []string{
	`CREATE TABLE projects (id INTEGER PRIMARY KEY, name TEXT, deleted_at DATETIME)`,
	`CREATE TABLE groups (id INTEGER PRIMARY KEY, name TEXT, description TEXT,
		created_at DATETIME, updated_at DATETIME, deleted_at DATETIME)`,
	`CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT,
		external_id TEXT, created_at DATETIME, updated_at DATETIME, deleted_at DATETIME)`,
	`CREATE TABLE roles (id INTEGER PRIMARY KEY, name TEXT, description TEXT,
		created_at DATETIME, updated_at DATETIME)`,
}

// TestMigrateDatabase_PreFoldedColumnsUpgrade is the regression: a pre-#1642
// database must migrate, not abort. Before the fix this failed on the very
// first folded-column backfill.
func TestMigrateDatabase_PreFoldedColumnsUpgrade(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pre1642.db"))
	require.NoError(t, err)

	for _, stmt := range preFoldedSchema {
		require.NoError(t, db.Exec(stmt).Error, "building the pre-#1642 fixture schema")
	}
	// Rows matter: backfillFoldedColumn returns early on an empty table, so an
	// empty fixture would pass even with the columns missing -- the read that
	// fails is the one that finds something to backfill.
	require.NoError(t, db.Exec(`INSERT INTO groups (id, name) VALUES (1, 'Engineering')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO users (id, username, email) VALUES (1, 'Ada', 'ada@example.com')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO roles (id, name) VALUES (1, 'admin')`).Error)

	// Confirm the fixture really is pre-#1642, so a future change to the schema
	// literals above cannot quietly turn this into a test of nothing.
	for _, c := range []struct{ table, column string }{
		{"groups", "name_folded"},
		{"users", "username_folded"},
		{"users", "email_folded"},
		{"roles", "name_folded"},
	} {
		require.Falsef(t, columnExists(db, c.table, c.column),
			"fixture must NOT already have %s.%s — with it present this test exercises the fresh-DB "+
				"shape and proves nothing about upgrades", c.table, c.column)
	}

	require.NoError(t, (&DefaultStorageFactory{}).migrateDatabase(db),
		"a database created before #1642 must migrate cleanly; this is what crash-looped the server")

	// And the columns must actually be there afterwards, not merely not-crashed.
	for _, c := range []struct{ table, column string }{
		{"groups", "name_folded"},
		{"users", "username_folded"},
		{"users", "email_folded"},
		{"roles", "name_folded"},
	} {
		require.Truef(t, columnExists(db, c.table, c.column),
			"%s.%s must exist after migrating a pre-#1642 database", c.table, c.column)
	}

	// The backfill must have run, not just the ADD COLUMN: a column full of
	// empty strings would satisfy the check above while leaving every lookup
	// and uniqueness check broken.
	var folded string
	require.NoError(t, db.Raw(`SELECT name_folded FROM groups WHERE id = 1`).Scan(&folded).Error)
	require.NotEmpty(t, folded, "groups.name_folded must be backfilled for pre-existing rows, not left empty")
}

// TestMigrateDatabase_RecreatesMFAStepUpGrantsOnUpgrade covers the other half
// of the same root cause: not a column added without an existing-DB step, but
// a whole TABLE.
//
// store-mfa-002 found that MFAStepUpGrant "was never migrated anywhere" and
// fixed it by adding the model to the bulk AutoMigrate list. That list sits
// after `if projectsExists { return nil }`, so the remedy only ever reached
// fresh installs -- the original finding was that the table existed on no
// database, and afterwards it still existed on no UPGRADED one. Exactly the
// shape of #1642's folded columns.
//
// The fixture drops the table from an already-migrated database rather than
// hand-building an old schema, because that is precisely what an older
// database IS from this code's point of view: everything else present,
// this one table absent.
func TestMigrateDatabase_RecreatesMFAStepUpGrantsOnUpgrade(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "stepup.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}

	require.NoError(t, f.migrateDatabase(db), "initial fresh migration")
	require.True(t, tableExists(db, "mfa_step_up_grants"),
		"sanity: a fresh install must have this table, or the rest of this test proves nothing")

	require.NoError(t, db.Exec("DROP TABLE mfa_step_up_grants").Error)
	require.False(t, tableExists(db, "mfa_step_up_grants"))

	// projects still exists, so this second run takes the existing-DB path --
	// the one a real upgrade takes.
	require.True(t, tableExists(db, "projects"),
		"the fixture must still look like an initialised database, or migrateDatabase takes the fresh path")
	require.NoError(t, f.migrateDatabase(db), "the upgrade path must run cleanly")

	require.True(t, tableExists(db, "mfa_step_up_grants"),
		"mfa_step_up_grants must be created on the existing-DB path. Without it, an upgraded install "+
			"cannot mint or read a step-up grant: the prune scheduler errors every cycle, and with "+
			"classification.restricted_requires_mfa_step_up enabled, checkRestrictedMFAGate turns the "+
			"missing-relation error into a permanent read failure on every restricted secret. It fails "+
			"closed, so this is lost availability rather than a bypass -- but it is a total break of the "+
			"tier meant for the most sensitive secrets, and unrecoverable in place, since minting a grant "+
			"needs the same missing table.")

	// Re-running must stay clean: the guard is an existence check, so a third
	// pass has to be a no-op rather than a duplicate-table error.
	require.NoError(t, f.migrateDatabase(db), "migrateDatabase must be idempotent across repeated upgrades")
}
