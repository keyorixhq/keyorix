// role_permission_generation_trigger_definition_postgres_test.go —
// TRIGGER-ROWDIGEST-1: the installer converges the trigger DEFINITION, not just
// its presence and enabled state, and leaves an already correct function row
// alone (role_permission_generation_integrity.go relies on both). Red on the
// base through behaviour: it re-created nothing and rewrote the function on
// every boot.
package store

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// revokeDirect removes the world's role->permission edge with direct SQL.
func revokeDirect(t *testing.T, db *gorm.DB, w rpgWorld) {
	t.Helper()
	require.NoError(t, db.Exec("DELETE FROM role_permissions WHERE role_id = ? AND permission_id = ?", w.role.ID, w.perm.ID).Error)
}

// TestRolePermissionGeneration_EnsureLeavesCorrectFunctionRowAlone_Postgres:
// a boot on a correct schema must not rewrite the function's pg_proc row, or
// every replica boot would read as tampering to every other replica.
func TestRolePermissionGeneration_EnsureLeavesCorrectFunctionRowAlone_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	db := w.writer.db
	xmin := func() string {
		var s string
		require.NoError(t, db.Raw("SELECT xmin::text FROM pg_proc WHERE oid = ?::regprocedure", rolePermGenerationFunc+"()").Scan(&s).Error)
		return s
	}
	before := xmin()
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	require.Equal(t, before, xmin(), "a correct function is left as it is")
}

// TestRolePermissionGeneration_EnsureRestoresRecreatedTrigger_Postgres: a
// trigger of the right name with fewer events passes the presence proof but
// misses a DELETE; the next boot must re-create it.
func TestRolePermissionGeneration_EnsureRestoresRecreatedTrigger_Postgres(t *testing.T) {
	w := rpgPostgresWorld(t)
	db := w.writer.db
	require.NoError(t, db.Exec("DROP TRIGGER "+RolePermissionsGenerationTrigger+" ON role_permissions").Error)
	require.NoError(t, db.Exec("CREATE TRIGGER "+RolePermissionsGenerationTrigger+" AFTER INSERT ON role_permissions FOR EACH STATEMENT EXECUTE PROCEDURE "+rolePermGenerationFunc+"()").Error)
	require.NoError(t, db.Exec("ALTER TABLE role_permissions ENABLE ALWAYS TRIGGER "+RolePermissionsGenerationTrigger).Error)
	require.NoError(t, EnsureRolePermissionsGenerationTriggers(db))
	var tgtype int
	require.NoError(t, db.Raw("SELECT tgtype FROM pg_trigger WHERE tgrelid = 'role_permissions'::regclass AND tgname = ?", RolePermissionsGenerationTrigger).Scan(&tgtype).Error)
	require.Equal(t, 60, tgtype, "AFTER ... FOR EACH STATEMENT on INSERT, UPDATE, DELETE and TRUNCATE")
	require.True(t, w.decide(t, w.perm.Name), "warm")
	revokeDirect(t, db, w)
	require.False(t, w.decide(t, w.perm.Name), "a direct DELETE bumps the generation again")
}
