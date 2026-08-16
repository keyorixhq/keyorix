package storage

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRolePKIsComplete_SQLite_OldTwoColumnPK verifies that rolePKIsComplete
// returns false when the table has the old two-column PK (user_id, role_id).
func TestRolePKIsComplete_SQLite_OldTwoColumnPK(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-detect-old.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id   INTEGER NOT NULL,
		role_id   INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id)
	)`).Error)

	assert.False(t, rolePKIsComplete(db, "user_roles"),
		"old two-column PK must be detected as incomplete")
}

// TestRolePKIsComplete_SQLite_OldThreeColumnPK verifies that rolePKIsComplete
// returns false when the table has the three-column PK (user_id, role_id,
// project_id) that the RBAC Phase 1 migration could produce — project_id is
// present but environment_id is missing from the PK.
func TestRolePKIsComplete_SQLite_OldThreeColumnPK(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-detect-three.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id    INTEGER NOT NULL,
		role_id    INTEGER NOT NULL,
		project_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id, project_id)
	)`).Error)

	assert.False(t, rolePKIsComplete(db, "user_roles"),
		"three-column PK without environment_id must be detected as incomplete")
}

// TestRolePKIsComplete_SQLite_NewFourColumnPK verifies that rolePKIsComplete
// returns true when the table already has the correct four-column composite PK.
func TestRolePKIsComplete_SQLite_NewFourColumnPK(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-detect-new.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id        INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id, project_id, environment_id)
	)`).Error)

	assert.True(t, rolePKIsComplete(db, "user_roles"),
		"four-column composite PK must be detected as complete")
}

// TestRolePKIsComplete_SQLite_ColumnsMentionedOutsidePKClause pins
// #STORAGE-FACTORY-002: the old detection heuristic did `strings.Contains` for
// "project_id"/"environment_id" against EVERY BYTE of the CREATE TABLE
// statement from the first "primary key" occurrence onward, not just the
// parenthesized PK column list — so it would false-positive (report the PK
// complete when it is not) on any DDL where those column names appear later in
// the statement for an unrelated reason, such as a trailing CHECK or FOREIGN
// KEY constraint that references them without them being PK members. This
// table's actual primary key is only (user_id, role_id); project_id and
// environment_id are ordinary columns referenced by a trailing CHECK
// constraint placed after "PRIMARY KEY (user_id, role_id)" in the DDL text.
func TestRolePKIsComplete_SQLite_ColumnsMentionedOutsidePKClause(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-detect-false-positive.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id        INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id),
		CHECK (project_id >= 0 AND environment_id >= 0)
	)`).Error)

	assert.False(t, rolePKIsComplete(db, "user_roles"),
		"project_id/environment_id mentioned only in a trailing CHECK constraint (not the PK clause) must not be reported as PK members")
}

// TestRebuildRolePKSQLite_OldTwoColumnPK_UserRoles exercises the full
// upgrade path for user_roles when the table has only a (user_id, role_id) PK.
// After the rebuild, the table must:
//   - carry the four-column composite PK
//   - preserve all pre-existing rows
//   - accept a new row that shares role_id with an existing row but has a
//     different project_id/environment_id scope (which would have violated the
//     old two-column PK).
func TestRebuildRolePKSQLite_OldTwoColumnPK_UserRoles(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-rebuild-user-old.db"))
	require.NoError(t, err)

	// Old schema: two-column PK.
	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id   INTEGER NOT NULL,
		role_id   INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id)
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id) VALUES (1, 10)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id) VALUES (2, 10)`).Error)

	// Add the missing columns that Phase 2 would add, so rebuildRolePKSQLite
	// can include them in the CREATE TABLE statement.
	require.NoError(t, db.Exec(`ALTER TABLE user_roles ADD COLUMN project_id     INTEGER NOT NULL DEFAULT 0`).Error)
	require.NoError(t, db.Exec(`ALTER TABLE user_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0`).Error)

	require.NoError(t, rebuildRolePKSQLite(db, "user_roles", "user_id", "user_id, role_id, project_id, environment_id"))

	// PK is now complete.
	assert.True(t, rolePKIsComplete(db, "user_roles"), "PK must be complete after rebuild")

	// Pre-existing data preserved.
	sqlDB, err := db.DB()
	require.NoError(t, err)

	var count int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&count))
	assert.Equal(t, 2, count, "both pre-existing rows must be preserved after PK rebuild")

	var roleID int
	require.NoError(t, sqlDB.QueryRow(`SELECT role_id FROM user_roles WHERE user_id = 1`).Scan(&roleID))
	assert.Equal(t, 10, roleID)

	// Can now insert the same role at a different scope — this would have violated
	// the old (user_id, role_id) PK.
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 10, 5, 0)`).Error,
		"inserting the same role at a different project scope must succeed after PK rebuild")

	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&count))
	assert.Equal(t, 3, count)
}

// TestRebuildRolePKSQLite_OldTwoColumnPK_GroupRoles mirrors the user_roles test
// for group_roles, confirming the rebuild works for both tables.
func TestRebuildRolePKSQLite_OldTwoColumnPK_GroupRoles(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-rebuild-group-old.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE group_roles (
		group_id INTEGER NOT NULL,
		role_id  INTEGER NOT NULL,
		PRIMARY KEY (group_id, role_id)
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id) VALUES (3, 20)`).Error)

	require.NoError(t, db.Exec(`ALTER TABLE group_roles ADD COLUMN project_id     INTEGER NOT NULL DEFAULT 0`).Error)
	require.NoError(t, db.Exec(`ALTER TABLE group_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0`).Error)

	require.NoError(t, rebuildRolePKSQLite(db, "group_roles", "group_id", "group_id, role_id, project_id, environment_id"))

	assert.True(t, rolePKIsComplete(db, "group_roles"), "PK must be complete after rebuild")

	// Can now insert the same role for the same group at a different scope.
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (3, 20, 7, 0)`).Error,
		"same role at different project scope must succeed after PK rebuild")
}

// TestRebuildRolePKSQLite_WithExpiresAt confirms that optional expires_at rows
// are copied across correctly during the SQLite table recreation.
func TestRebuildRolePKSQLite_WithExpiresAt(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "pk-rebuild-expires.db"))
	require.NoError(t, err)

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id    INTEGER NOT NULL,
		role_id    INTEGER NOT NULL,
		expires_at TIMESTAMP WITH TIME ZONE,
		PRIMARY KEY (user_id, role_id)
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id, expires_at) VALUES (1, 5, '2030-01-01 00:00:00')`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id, expires_at) VALUES (2, 5, NULL)`).Error)

	require.NoError(t, db.Exec(`ALTER TABLE user_roles ADD COLUMN project_id     INTEGER NOT NULL DEFAULT 0`).Error)
	require.NoError(t, db.Exec(`ALTER TABLE user_roles ADD COLUMN environment_id INTEGER NOT NULL DEFAULT 0`).Error)

	require.NoError(t, rebuildRolePKSQLite(db, "user_roles", "user_id", "user_id, role_id, project_id, environment_id"))

	sqlDB, err := db.DB()
	require.NoError(t, err)

	var expiresAt *string
	require.NoError(t, sqlDB.QueryRow(`SELECT expires_at FROM user_roles WHERE user_id = 1 AND role_id = 5`).Scan(&expiresAt))
	require.NotNil(t, expiresAt, "expires_at must be preserved for the timed row")
	assert.True(t, strings.Contains(*expiresAt, "2030"), "expires_at value must be retained")

	require.NoError(t, sqlDB.QueryRow(`SELECT expires_at FROM user_roles WHERE user_id = 2 AND role_id = 5`).Scan(&expiresAt))
	assert.Nil(t, expiresAt, "NULL expires_at must remain NULL after rebuild")
}

// TestRebuildRolePKIfNeeded_SQLite_EndToEnd exercises the full migrateDatabase
// upgrade path: seed old-schema tables, run migrateDatabase, verify that the PK
// is rebuilt and data is preserved — the same contract the real field upgrade path
// delivers.
func TestRebuildRolePKIfNeeded_SQLite_EndToEnd(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pk-rebuild-e2e.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Simulate a GORM-created DB from before the composite PK: two-column PK only.
	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id   INTEGER NOT NULL,
		role_id   INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id)
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE group_roles (
		group_id INTEGER NOT NULL,
		role_id  INTEGER NOT NULL,
		PRIMARY KEY (group_id, role_id)
	)`).Error)

	// Seed data (use distinct role IDs per table to avoid accidental collision).
	require.NoError(t, db.Exec(`INSERT INTO user_roles  (user_id,  role_id) VALUES (1, 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles  (user_id,  role_id) VALUES (2, 2)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id) VALUES (1, 3)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id) VALUES (2, 4)`).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	// Both tables must now carry the full four-column composite PK.
	assert.True(t, rolePKIsComplete(db, "user_roles"),
		"user_roles must have the four-column composite PK after migrateDatabase")
	assert.True(t, rolePKIsComplete(db, "group_roles"),
		"group_roles must have the four-column composite PK after migrateDatabase")

	// All pre-existing rows must survive the rebuild.
	sqlDB, rawErr := db.DB()
	require.NoError(t, rawErr)

	var cnt int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&cnt))
	assert.Equal(t, 2, cnt, "both user_roles rows must survive the PK rebuild")

	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM group_roles`).Scan(&cnt))
	assert.Equal(t, 2, cnt, "both group_roles rows must survive the PK rebuild")

	// Post-rebuild: the same role can now be assigned at two different project
	// scopes (the core invariant this migration restores).
	require.NoError(t, db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 5, 0)`,
	).Error, "same role at a different project scope must succeed after PK rebuild")

	require.NoError(t, db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 3, 7, 2)`,
	).Error, "same role at a different environment scope must succeed after PK rebuild")

	// migrateDatabase is idempotent: re-running must succeed without error.
	require.NoError(t, f.migrateDatabase(db),
		"migrateDatabase must be idempotent — re-running must succeed")
}

// TestRebuildRolePKIfNeeded_SQLite_AlreadyComplete confirms that
// rebuildRolePKIfNeeded is a no-op when both tables already have the correct
// four-column PK (i.e. a fresh install — the common case on every boot after
// the first).
func TestRebuildRolePKIfNeeded_SQLite_AlreadyComplete(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pk-rebuild-noop.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Tables with the correct PK already — no rebuild should be needed.
	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id        INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id, project_id, environment_id)
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE group_roles (
		group_id       INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (group_id, role_id, project_id, environment_id)
	)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles  VALUES (1, 1, 0, 0)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles VALUES (1, 1, 0, 0)`).Error)

	require.NoError(t, rebuildRolePKIfNeeded(db))

	// Data must be untouched.
	sqlDB, rawErr := db.DB()
	require.NoError(t, rawErr)

	var cnt int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&cnt))
	assert.Equal(t, 1, cnt, "no-op path must leave existing rows in place")
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM group_roles`).Scan(&cnt))
	assert.Equal(t, 1, cnt)
}
