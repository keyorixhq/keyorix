package storage

// factory_rbac_pk_rebuild_postgres_test.go — the real-Postgres counterpart to
// factory_rbac_pk_rebuild_test.go. That file's tests are SQLite-only
// (gormOpenForTest), which is exactly why rebuildRolePKPostgres sat at 0.0%
// coverage and rolePKIsComplete's Postgres branch at 57.1% (see this
// campaign's report): TestCreateStorage_Postgres_FailsFast (storage_s2_test.go)
// only ever drives createPostgresStorage's connection-refused branch, never
// far enough to reach migrateDatabase → rebuildRolePKIfNeeded against a live
// server. If rolePKIsComplete's Postgres branch ever misdetects "PK already
// correct" when it isn't, rebuildRolePKIfNeeded silently skips the rebuild —
// no error, no log — and a production Postgres deployment keeps the stale
// 2-column PK indefinitely.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRolePKIsComplete_Postgres_OldTwoColumnPK is the Postgres counterpart to
// TestRolePKIsComplete_SQLite_OldTwoColumnPK.
func TestRolePKIsComplete_Postgres_OldTwoColumnPK(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id   INTEGER NOT NULL,
		role_id   INTEGER NOT NULL,
		PRIMARY KEY (user_id, role_id)
	)`).Error)

	assert.False(t, rolePKIsComplete(db, "user_roles"),
		"old two-column PK must be detected as incomplete on Postgres")
}

// TestRolePKIsComplete_Postgres_NewFourColumnPK is the Postgres counterpart to
// TestRolePKIsComplete_SQLite_NewFourColumnPK.
func TestRolePKIsComplete_Postgres_NewFourColumnPK(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id        INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id, project_id, environment_id)
	)`).Error)

	assert.True(t, rolePKIsComplete(db, "user_roles"),
		"four-column composite PK must be detected as complete on Postgres")
}

// TestRolePKIsComplete_Postgres_ColumnsMentionedOutsidePKClause is the
// Postgres counterpart to TestRolePKIsComplete_SQLite_ColumnsMentionedOutsidePKClause
// (#STORAGE-FACTORY-002) — project_id/environment_id exist as ordinary
// columns referenced only by a CHECK constraint, not as PK members.
// rolePKIsComplete's Postgres branch queries information_schema.key_column_usage
// joined against table_constraints filtered to constraint_type = 'PRIMARY KEY',
// so this is a different code path from the SQLite pragma_table_info version —
// worth pinning independently, not just inferring from the SQLite result.
func TestRolePKIsComplete_Postgres_ColumnsMentionedOutsidePKClause(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	require.NoError(t, db.Exec(`CREATE TABLE user_roles (
		user_id        INTEGER NOT NULL,
		role_id        INTEGER NOT NULL,
		project_id     INTEGER NOT NULL DEFAULT 0,
		environment_id INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, role_id),
		CHECK (project_id >= 0 AND environment_id >= 0)
	)`).Error)

	assert.False(t, rolePKIsComplete(db, "user_roles"),
		"project_id/environment_id mentioned only in a CHECK constraint (not the PK clause) must not be reported as PK members on Postgres")
}

// TestRebuildRolePKIfNeeded_Postgres_EndToEnd is the Postgres counterpart to
// TestRebuildRolePKIfNeeded_SQLite_EndToEnd: a stale 2-column PK on both
// user_roles and group_roles, with pre-existing data, rebuilt via
// migrateDatabase (which on Postgres routes through rebuildRolePKPostgres,
// never exercised end-to-end against a live server before this test) into
// the correct 4-column composite PK — data preserved, and the actual
// multi-project-scope grant this PK exists to allow now succeeds.
func TestRebuildRolePKIfNeeded_Postgres_EndToEnd(t *testing.T) {
	base := pgTestDSN(t)
	db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, base))

	// Simulate a pre-#OLD-PK-fix Postgres schema: two-column PK only.
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

	require.NoError(t, db.Exec(`INSERT INTO user_roles  (user_id,  role_id) VALUES (1, 1)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO user_roles  (user_id,  role_id) VALUES (2, 2)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id) VALUES (1, 3)`).Error)
	require.NoError(t, db.Exec(`INSERT INTO group_roles (group_id, role_id) VALUES (2, 4)`).Error)

	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	assert.True(t, rolePKIsComplete(db, "user_roles"),
		"user_roles must have the four-column composite PK after migrateDatabase on Postgres")
	assert.True(t, rolePKIsComplete(db, "group_roles"),
		"group_roles must have the four-column composite PK after migrateDatabase on Postgres")

	sqlDB, err := db.DB()
	require.NoError(t, err)

	var cnt int
	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM user_roles`).Scan(&cnt))
	assert.Equal(t, 2, cnt, "both user_roles rows must survive the PK rebuild on Postgres")

	require.NoError(t, sqlDB.QueryRow(`SELECT COUNT(*) FROM group_roles`).Scan(&cnt))
	assert.Equal(t, 2, cnt, "both group_roles rows must survive the PK rebuild on Postgres")

	// Post-rebuild: the same role can now be assigned at a second project
	// scope — the core invariant this migration restores, and exactly what
	// the stale 2-column PK made impossible (UNIQUE (user_id, role_id) would
	// have rejected this as a duplicate key).
	require.NoError(t, db.Exec(
		`INSERT INTO user_roles (user_id, role_id, project_id, environment_id) VALUES (1, 1, 5, 0)`,
	).Error, "same role at a different project scope must succeed after PK rebuild on Postgres")
	require.NoError(t, db.Exec(
		`INSERT INTO group_roles (group_id, role_id, project_id, environment_id) VALUES (1, 3, 7, 2)`,
	).Error, "same role at a different environment scope must succeed after PK rebuild on Postgres")

	// Idempotent: re-running migrateDatabase against the now-correct schema
	// must not error (this also exercises rolePKIsComplete's true-branch
	// early continue inside rebuildRolePKIfNeeded's loop on a live server).
	require.NoError(t, f.migrateDatabase(db),
		"migrateDatabase must be idempotent on Postgres — re-running must succeed")
}
