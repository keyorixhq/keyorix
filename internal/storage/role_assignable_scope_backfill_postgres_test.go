package storage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestRoleAssignableScopeBackfill_Postgres is the real-Postgres counterpart of
// role_assignable_scope_backfill_test.go: the upgrade backfill, its
// idempotence, and the column rolling back with a failed backfill.
func TestRoleAssignableScopeBackfill_Postgres(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	t.Run("upgrade is once and idempotent", func(t *testing.T) {
		db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
		f := &DefaultStorageFactory{}
		require.NoError(t, f.migrateDatabase(db))
		seedPreEpoch6Roles(t, db)

		require.NoError(t, f.migrateDatabase(db))
		got := roleAssignableScopes(t, db)
		assert.Equal(t, models.RoleAssignableAny, got["deploy-bot"])
		for name, want := range models.BuiltinRoleAssignableScopes {
			assert.Equal(t, want, got[name], "built-in %s", name)
		}
		require.NoError(t, db.Exec(`UPDATE roles SET assignable_scope = 'project' WHERE name = 'deploy-bot'`).Error)
		before := roleAssignableScopes(t, db)
		require.NoError(t, f.migrateDatabase(db))
		assert.Equal(t, before, roleAssignableScopes(t, db))
	})

	t.Run("failed backfill leaves no column", func(t *testing.T) {
		db := pgRawOpen(t, pgIsolatedDatabaseDSN(t, pgTestDSN(t)))
		f := &DefaultStorageFactory{}
		require.NoError(t, f.migrateDatabase(db))
		seedPreEpoch6Roles(t, db)
		require.NoError(t, db.Exec(`CREATE FUNCTION fail_role_backfill() RETURNS trigger AS $$
			BEGIN RAISE EXCEPTION 'injected backfill failure'; END $$ LANGUAGE plpgsql`).Error)
		require.NoError(t, db.Exec(`CREATE TRIGGER fail_role_backfill BEFORE UPDATE ON roles
			FOR EACH ROW EXECUTE FUNCTION fail_role_backfill()`).Error)

		require.Error(t, f.migrateDatabase(db))
		assert.False(t, columnExists(db, "roles", "assignable_scope"), "the column must roll back with the failed backfill")

		require.NoError(t, db.Exec(`DROP TRIGGER fail_role_backfill ON roles`).Error)
		require.NoError(t, f.migrateDatabase(db))
		assert.Equal(t, models.RoleAssignableGlobal, roleAssignableScopes(t, db)["system_admin"])
	})
}
