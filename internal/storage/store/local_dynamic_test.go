package store

import (
	"context"
	"errors"
	"testing"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newDynamicConfigTestStore builds a LocalStorage over real SQLite with the
// dynamic_secret_configs unique index installed, mirroring
// ensureDynamicSecretConfigNameIndex in factory.go exactly (#462), so these tests
// exercise the same DB-level guard production installs get.
func newDynamicConfigTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name "+
		"ON dynamic_secret_configs (project_id, environment_id, name)").Error)
	return NewLocalStorage(db)
}

// TestCreateDynamicSecretConfig_DuplicateNameRejected is the (#462) regression:
// DynamicSecretConfig's doc comment states "one per (project, env, name)" but
// nothing enforced it. A second create for the identical (project, environment,
// name) tuple must fail with the translated sentinel, not silently create a
// second row nor surface a raw constraint-violation message.
func TestCreateDynamicSecretConfig_DuplicateNameRejected(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicConfigTestStore(t)

	first, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	require.NoError(t, err)
	assert.NotZero(t, first.ID)

	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	require.Error(t, err, "a second config with the identical (project, env, name) tuple must be rejected")
	assert.True(t, errors.Is(err, coreStorage.ErrDuplicateDynamicSecretConfig),
		"the duplicate must be translated to the sentinel, not surfaced as a raw constraint-violation error")

	var count int64
	require.NoError(t, ls.db.Model(&models.DynamicSecretConfig{}).
		Where("project_id = ? AND environment_id = ? AND name = ?", 1, 2, "app-db").
		Count(&count).Error)
	assert.Equal(t, int64(1), count, "only one row must exist for the duplicate tuple")
}

// TestCreateDynamicSecretConfig_DifferentScopeAllowed asserts the unique index is
// scoped to the full (project, environment, name) tuple: different environments,
// different projects, or a different name for the same (project, environment) must
// all succeed independently.
func TestCreateDynamicSecretConfig_DifferentScopeAllowed(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicConfigTestStore(t)

	_, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	require.NoError(t, err)

	// Same project + name, different environment.
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 3, BackendType: "postgres",
	})
	assert.NoError(t, err, "the same name in a different environment must succeed")

	// Different project, same environment ID + name.
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 2, EnvironmentID: 2, BackendType: "postgres",
	})
	assert.NoError(t, err, "the same name in a different project must succeed")

	// Same project + environment, different name.
	_, err = ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "other-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	assert.NoError(t, err, "a different name in the same project/environment must succeed")
}
