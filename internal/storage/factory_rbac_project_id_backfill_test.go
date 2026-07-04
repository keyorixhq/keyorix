package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRBACPhase2Backfill_NullProjectIDNormalisedToZero pins the RBAC Phase 2
// backfill loop in migrateDatabase (the `for _, tbl := range []string{
// "user_roles", "group_roles"} { ... UPDATE %s SET project_id = 0 WHERE
// project_id IS NULL ... }` block): it never actually ran on SQLite until the
// #490/#761 columnExists/tableExists dialect fix, because tableExists(db,
// tbl) always returned false on SQLite before that fix, so the loop body's
// `continue` fired unconditionally and the UPDATE was unreachable code on
// every SQLite boot.
//
// Simulate a genuinely pre-008 legacy install: user_roles/group_roles tables
// created directly via raw SQL in the old nullable-project_id shape (no
// environment_id column at all, project_id with no NOT NULL/default), with a
// row seeded with project_id IS NULL via a raw INSERT — GORM's own
// model-based Create can never produce that NULL today, since
// models.UserRole/GroupRole now declare ProjectID as `uint` with
// `not null;default:0`. Re-running migrateDatabase directly (the same entry
// point a real process boot calls) must both add the missing environment_id
// column and normalise the NULL project_id row to the 0 = global sentinel the
// authorization queries expect — verified via a raw column scan (not a GORM
// struct scan, which would mask a NULL by coercing it into a zero uint
// regardless of what is actually stored).
func TestRBACPhase2Backfill_NullProjectIDNormalisedToZero(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rbac-phase2-backfill.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	// Legacy pre-008 shape: no environment_id column, project_id nullable.
	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		project_id INTEGER,
		PRIMARY KEY (user_id, role_id, project_id)
	)`).Error)
	require.NoError(t, db.Exec(`CREATE TABLE group_roles (
		group_id INTEGER NOT NULL,
		role_id INTEGER NOT NULL,
		project_id INTEGER,
		PRIMARY KEY (group_id, role_id, project_id)
	)`).Error)

	// A legacy NULL-project_id row (the exact pre-008 shape) plus an
	// already-scoped row that must be left untouched by the backfill.
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id, project_id) VALUES (1, 1, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles (user_id, role_id, project_id) VALUES (2, 1, 5)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id, project_id) VALUES (1, 1, NULL)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id, project_id) VALUES (2, 1, 5)`).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	assert.True(t, columnExists(db, "user_roles", "environment_id"), "environment_id must be backfilled onto user_roles")
	assert.True(t, columnExists(db, "group_roles", "environment_id"), "environment_id must be backfilled onto group_roles")

	sqlDB, err := db.DB()
	require.NoError(t, err)

	var userRoleProjectID int
	require.NoError(t, sqlDB.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 1 AND role_id = 1`).Scan(&userRoleProjectID))
	assert.Equal(t, 0, userRoleProjectID, "legacy NULL project_id on user_roles must be normalised to the 0 = global sentinel")

	var groupRoleProjectID int
	require.NoError(t, sqlDB.QueryRow(`SELECT project_id FROM group_roles WHERE group_id = 1 AND role_id = 1`).Scan(&groupRoleProjectID))
	assert.Equal(t, 0, groupRoleProjectID, "legacy NULL project_id on group_roles must be normalised to the 0 = global sentinel")

	// The already-scoped rows must be left exactly as they were.
	var scopedUserRoleProjectID int
	require.NoError(t, sqlDB.QueryRow(`SELECT project_id FROM user_roles WHERE user_id = 2 AND role_id = 1`).Scan(&scopedUserRoleProjectID))
	assert.Equal(t, 5, scopedUserRoleProjectID, "an already-scoped user_roles row must not be touched by the backfill")

	var scopedGroupRoleProjectID int
	require.NoError(t, sqlDB.QueryRow(`SELECT project_id FROM group_roles WHERE group_id = 2 AND role_id = 1`).Scan(&scopedGroupRoleProjectID))
	assert.Equal(t, 5, scopedGroupRoleProjectID, "an already-scoped group_roles row must not be touched by the backfill")
}
