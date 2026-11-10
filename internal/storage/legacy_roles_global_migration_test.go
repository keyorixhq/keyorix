package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLegacyRolesTightenedOnExistingDatabase: a database that already has
// roles.assignable_scope, with the legacy roles at any as the epoch-7 backfill
// left them, gets them at global on the next boot (#3605). Nothing else moves:
// a custom any role stays any, and no grant row is changed. Red without
// tightenLegacyRolesToGlobal: only the seed table changed, and neither seeding
// nor the backfill runs again on an existing database.
func TestLegacyRolesTightenedOnExistingDatabase(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legacy-global.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))

	legacy := models.LegacyRoleNames()
	require.Len(t, legacy, 5)
	for _, name := range append([]string{"deploy-bot"}, legacy...) {
		require.NoError(t, db.Exec(`INSERT INTO roles (name, name_folded, description, bypasses_permission_checks, assignable_scope) VALUES (?, ?, '', false, 'any')`,
			name, name).Error)
	}
	var viewer models.Role
	require.NoError(t, db.Where("name = ?", "viewer").First(&viewer).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: viewer.ID, ProjectID: 2}).Error)
	require.NoError(t, db.Create(&models.MachineIdentityRole{MachineIdentityID: 4, RoleID: viewer.ID, ProjectID: 2}).Error)

	require.NoError(t, f.migrateDatabase(db), "upgrade boot")
	got := roleAssignableScopes(t, db)
	for _, name := range legacy {
		assert.Equal(t, models.RoleAssignableGlobal, got[name], "legacy role %s", name)
	}
	assert.Equal(t, models.RoleAssignableAny, got["deploy-bot"], "a custom role keeps its scope")

	var users, machines int64
	require.NoError(t, db.Model(&models.UserRole{}).Where("role_id = ? AND project_id = 2", viewer.ID).Count(&users).Error)
	require.NoError(t, db.Model(&models.MachineIdentityRole{}).Where("role_id = ? AND project_id = 2", viewer.ID).Count(&machines).Error)
	assert.Equal(t, int64(1), users, "the migration must not touch an existing grant")
	assert.Equal(t, int64(1), machines, "the migration must not touch an existing grant")

	before := roleAssignableScopes(t, db)
	require.NoError(t, f.migrateDatabase(db), "second boot")
	assert.Equal(t, before, roleAssignableScopes(t, db), "idempotent")
}

// TestLegacyRolesTighten_FailureFailsTheBoot: fail closed. A boot that could not
// tighten the roles must not serve while they still accept project grants.
func TestLegacyRolesTighten_FailureFailsTheBoot(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "legacy-global-fail.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	require.NoError(t, db.Exec(`INSERT INTO roles (name, name_folded, description, bypasses_permission_checks, assignable_scope) VALUES ('viewer', 'viewer', '', false, 'any')`).Error)
	require.NoError(t, db.Exec(`CREATE TRIGGER fail_legacy_tighten BEFORE UPDATE ON roles BEGIN SELECT RAISE(ABORT, 'injected failure'); END`).Error)

	require.ErrorContains(t, f.migrateDatabase(db), "legacy roles' assignable scope")

	require.NoError(t, db.Exec(`DROP TRIGGER fail_legacy_tighten`).Error)
	require.NoError(t, f.migrateDatabase(db), "the next boot applies it")
	assert.Equal(t, models.RoleAssignableGlobal, roleAssignableScopes(t, db)["viewer"])
}
