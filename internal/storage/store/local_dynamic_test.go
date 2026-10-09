package store

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newDynamicConfigTestStore builds a LocalStorage over real SQLite with the
// dynamic_secret_configs unique index installed, mirroring
// ensureDynamicSecretConfigNameIndex in factory.go exactly (#462), so these tests
// exercise the same DB-level guard production installs get.
func newDynamicConfigTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))
	require.NoError(t, db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS uniq_dynamic_secret_configs_project_env_name "+
		"ON dynamic_secret_configs (project_id, environment_id, name)").Error)
	seedDynamicConfigProjects(t, db)
	return NewLocalStorage(db)
}

// seedDynamicConfigProjects creates live projects 1 and 2, the projects the dynamic
// config tests in this package create configs in: CreateDynamicSecretConfig refuses a
// config whose project is missing or soft-deleted (#2651, INV-STORE-21).
func seedDynamicConfigProjects(t *testing.T, db *gorm.DB) {
	t.Helper()
	require.NoError(t, db.AutoMigrate(&models.Project{}))
	for _, id := range []uint{1, 2} {
		require.NoError(t, db.Create(&models.Project{ID: id, Name: fmt.Sprintf("dyn-project-%d", id)}).Error)
	}
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

// TestCreateDynamicSecretLease_ActiveRefusedOnDisabledConfig: the single-process half
// of INV-STORE-21 for leases (#2652). An ACTIVE lease against a disabled config is
// refused with ErrDynamicSecretConfigDisabled and leaves no row; a revoke_failed
// tracking row for the same config is still recorded, because it is the only record
// of a credential still live on the target.
func TestCreateDynamicSecretLease_ActiveRefusedOnDisabledConfig(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicConfigTestStore(t)
	require.NoError(t, ls.db.AutoMigrate(&models.DynamicSecretLease{}))
	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(cfg).Update("disabled", true).Error)

	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: "lease-active", RoleName: "r1", Status: "active",
	})
	require.ErrorIs(t, err, coreStorage.ErrDynamicSecretConfigDisabled)

	_, err = ls.CreateDynamicSecretLease(ctx, &models.DynamicSecretLease{
		ConfigID: cfg.ID, LeaseID: "lease-orphan", RoleName: "r2", Status: "revoke_failed",
	})
	require.NoError(t, err, "a revoke_failed tracking row must be recorded even under a disabled config")

	leases, err := ls.ListDynamicSecretLeases(ctx, cfg.ID)
	require.NoError(t, err)
	require.Len(t, leases, 1)
	assert.Equal(t, "lease-orphan", leases[0].LeaseID, "the refused active lease must have been rolled back")
}

// TestSetDynamicSecretConfigAdminDSN_LeavesDisabledAlone (#2651): the DSN write after
// insert touches only the DSN columns, so a concurrent #369 disable that landed between
// the insert and this write survives it (a full-row Save wrote disabled=false back).
func TestSetDynamicSecretConfigAdminDSN_LeavesDisabledAlone(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicConfigTestStore(t)
	cfg, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 1, EnvironmentID: 2, BackendType: "postgres",
	})
	require.NoError(t, err)
	require.NoError(t, ls.db.Model(&models.DynamicSecretConfig{}).Where("id = ?", cfg.ID).Update("disabled", true).Error)

	require.NoError(t, ls.SetDynamicSecretConfigAdminDSN(ctx, cfg.ID, []byte("enc"), []byte("meta")))

	got, err := ls.GetDynamicSecretConfig(ctx, cfg.ID)
	require.NoError(t, err)
	assert.True(t, got.Disabled, "the DSN write must not re-enable a disabled config")
	assert.Equal(t, []byte("enc"), got.AdminDSNEnc)
	assert.Equal(t, []byte("meta"), got.AdminDSNMeta)
	assert.Error(t, ls.SetDynamicSecretConfigAdminDSN(ctx, cfg.ID+1000, nil, nil), "no matching row is an error")
}

// TestCreateDynamicSecretConfig_RefusesSoftDeletedProject: the single-process half of
// INV-STORE-21 for configs (#2651). A config in a soft-deleted project is refused and
// leaves no row: DeleteProject's #369 disable already ran, so it would stay enabled.
func TestCreateDynamicSecretConfig_RefusesSoftDeletedProject(t *testing.T) {
	ctx := context.Background()
	ls := newDynamicConfigTestStore(t)
	require.NoError(t, ls.db.Delete(&models.Project{}, 2).Error)

	_, err := ls.CreateDynamicSecretConfig(ctx, &models.DynamicSecretConfig{
		Name: "app-db", ProjectID: 2, EnvironmentID: 2, BackendType: "postgres",
	})
	require.Error(t, err)
	var n int64
	require.NoError(t, ls.db.Model(&models.DynamicSecretConfig{}).Where("project_id = ?", 2).Count(&n).Error)
	assert.Zero(t, n, "the refused config must have been rolled back")
}
