package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRoleNameFoldedColumn_AddedOnUpgrade pins a critical regression:
// ensureRoleNameIndex (#1642, roles.name_folded) was only ever wired into
// migrateDatabase's fresh-install tail block, never into the additive,
// existing-DB-safe path every sibling *_folded column (groups.name_folded,
// users.username_folded/email_folded) correctly uses. Since migrateDatabase
// returns early once the projects table already exists, an upgrade of any
// real pre-existing installation never ran ensureRoleNameIndex at all --
// roles.name_folded was never added -- while models.Role and
// LocalStorage.CreateRole/UpdateRole unconditionally reference that column
// in every generated INSERT/UPDATE, breaking role creation/update outright
// with a "no such column" error the first time either was called after
// upgrading. Mirrors TestCompanionIndexes_CreatedOnUpgrade's established
// simulate-an-upgrade pattern: boot fresh (creates the column via the
// fresh-DB tail, matching a real fresh install), remove it to stand in for
// "this install predates the fix", then re-run migrateDatabase exactly as a
// real second process boot does and confirm it re-converges.
func TestRoleNameFoldedColumn_AddedOnUpgrade(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "role-name-folded-upgrade.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}

	// First boot: genuinely fresh database. projects doesn't exist yet, so
	// the full AutoMigrate block + fresh-DB tail run, adding name_folded.
	require.NoError(t, f.migrateDatabase(db))
	require.True(t, columnExists(db, "roles", "name_folded"), "fresh install must have name_folded via the AutoMigrate+fresh-tail path")

	// Remove it, standing in for an install that upgraded through an older
	// binary that predates this fix (roles table present, name_folded never
	// added because the wiring bug skipped ensureRoleNameIndex entirely).
	require.NoError(t, db.Exec("DROP INDEX IF EXISTS uniq_roles_name_folded").Error)
	require.NoError(t, db.Exec("ALTER TABLE roles DROP COLUMN name_folded").Error)
	require.False(t, columnExists(db, "roles", "name_folded"), "name_folded must actually be gone before re-running the migration")

	// Second run: mirrors exactly what a real process boot does on an
	// existing (projects table present) database.
	require.NoError(t, f.migrateDatabase(db))

	assert.True(t, columnExists(db, "roles", "name_folded"), "name_folded must be re-added on an upgraded install, not just a fresh one")
	assert.True(t, indexExists(db, "uniq_roles_name_folded"), "the unique index on name_folded must be re-created on an upgraded install too")
}

// TestSecretNodeNameNFC_NormalizedOnUpgrade is the sibling regression test
// for ensureSecretNodeNameNFC, which had the identical wiring gap:
// secret_nodes.name was never NFC-normalized on an upgrade of an existing
// installation, only on a fresh install.
func TestSecretNodeNameNFC_NormalizedOnUpgrade(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "secretnode-nfc-upgrade.db")
	db, err := gormOpenForTest(t, dbPath)
	require.NoError(t, err)

	f := &DefaultStorageFactory{}

	// Fresh boot to get the real, fully-migrated schema (all tables/columns
	// present), matching a genuine fresh install.
	require.NoError(t, f.migrateDatabase(db))

	// Simulate an existing installation with a pre-#1642 secret whose name
	// was stored in NFD form (the exact scenario ensureSecretNodeNameNFC
	// exists to fix). Requires a real project/environment row to satisfy
	// secret_nodes' foreign keys.
	require.NoError(t, db.Exec(`INSERT INTO projects (id, name, created_at, updated_at) VALUES (1, 'p', datetime('now'), datetime('now'))`).Error)
	require.NoError(t, db.Exec(`INSERT INTO environments (id, project_id, name, created_at, updated_at) VALUES (1, 1, 'e', datetime('now'), datetime('now'))`).Error)
	require.NoError(t, db.Exec(`INSERT INTO secret_nodes (id, project_id, environment_id, name, type, created_at, updated_at) VALUES (1, 1, 1, ?, 'static', datetime('now'), datetime('now'))`, nfdCafe).Error)

	// Re-run migrateDatabase exactly as a real second process boot does
	// against this now-existing (projects table present) database.
	require.NoError(t, f.migrateDatabase(db))

	var got string
	require.NoError(t, db.Table("secret_nodes").Where("id = 1").Select("name").Scan(&got).Error)
	assert.Equal(t, nfcCafe, got, "a pre-existing NFD secret name must be NFC-normalized on an upgraded install, not just a fresh one")
}
