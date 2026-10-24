package storage

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// seedPreEpoch6Roles turns a migrated database back into the pre-epoch-6
// shape (no roles.assignable_scope) holding every built-in role plus one custom
// role, the way an install upgraded from epoch 5 looks.
func seedPreEpoch6Roles(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.Exec(`ALTER TABLE roles DROP COLUMN assignable_scope`).Error)
	require.False(t, columnExists(db, "roles", "assignable_scope"))
	names := []string{"deploy-bot"} // a custom role an install relies on
	for name := range models.BuiltinRoleAssignableScopes {
		names = append(names, name)
	}
	for _, name := range names {
		require.NoError(t, db.Exec(`INSERT INTO roles (name, name_folded, description, bypasses_permission_checks) VALUES (?, ?, '', false)`,
			name, name).Error)
	}
}

func roleAssignableScopes(t *testing.T, db *gorm.DB) map[string]string {
	t.Helper()
	var rows []struct{ Name, AssignableScope string }
	require.NoError(t, db.Raw(`SELECT name, assignable_scope FROM roles`).Scan(&rows).Error)
	out := map[string]string{}
	for _, r := range rows {
		out[r.Name] = r.AssignableScope
	}
	return out
}

// TestRoleAssignableScopeBackfill_UpgradeIsOnceAndIdempotent pins the epoch-6
// migration (GROUP-ROLE-SCOPE-1 Phase 2, #3546): an existing custom role
// becomes any (nothing that worked breaks), each built-in its fixed scope, a
// new role defaults to project, and a second and third boot change nothing:
// in particular an admin's later edit is never reset by a re-run backfill.
func TestRoleAssignableScopeBackfill_UpgradeIsOnceAndIdempotent(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "assignable-scope.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	seedPreEpoch6Roles(t, db)

	require.NoError(t, f.migrateDatabase(db), "upgrade boot")
	got := roleAssignableScopes(t, db)
	assert.Equal(t, models.RoleAssignableAny, got["deploy-bot"], "an existing custom role must be backfilled to any")
	for name, want := range models.BuiltinRoleAssignableScopes {
		assert.Equal(t, want, got[name], "built-in %s", name)
	}

	// The column default is the NEW-role default.
	require.NoError(t, db.Exec(`INSERT INTO roles (name, name_folded, description, bypasses_permission_checks) VALUES ('fresh', 'fresh', '', false)`).Error)
	assert.Equal(t, models.RoleAssignableProject, roleAssignableScopes(t, db)["fresh"], "a role written without the column gets project")

	// An admin narrows the custom role; later boots must not undo it.
	require.NoError(t, db.Exec(`UPDATE roles SET assignable_scope = 'project' WHERE name = 'deploy-bot'`).Error)
	before := roleAssignableScopes(t, db)
	require.NoError(t, f.migrateDatabase(db), "second boot")
	require.NoError(t, f.migrateDatabase(db), "third boot")
	assert.Equal(t, before, roleAssignableScopes(t, db), "a re-run migration must change no role's assignable scope")
}

// TestRoleAssignableScopeBackfill_FailureLeavesNoColumn: the column and its
// backfill commit together. If the backfill fails, the column must not stay
// behind, because its presence is what tells the next boot the backfill ran.
// Left behind, every role (system_admin included) would read as project-only.
func TestRoleAssignableScopeBackfill_FailureLeavesNoColumn(t *testing.T) {
	db, err := gormOpenForTest(t, filepath.Join(t.TempDir(), "assignable-scope-fail.db"))
	require.NoError(t, err)
	f := &DefaultStorageFactory{}
	require.NoError(t, f.migrateDatabase(db))
	seedPreEpoch6Roles(t, db)
	require.NoError(t, db.Exec(`CREATE TRIGGER fail_role_backfill BEFORE UPDATE ON roles BEGIN SELECT RAISE(ABORT, 'injected backfill failure'); END`).Error)

	require.Error(t, f.migrateDatabase(db), "a failed backfill must fail the boot")
	assert.False(t, columnExists(db, "roles", "assignable_scope"), "the column must roll back with the failed backfill")

	require.NoError(t, db.Exec(`DROP TRIGGER fail_role_backfill`).Error)
	require.NoError(t, f.migrateDatabase(db), "the next boot runs the backfill")
	assert.Equal(t, models.RoleAssignableGlobal, roleAssignableScopes(t, db)["system_admin"])
}
