package store

// #4287: LocalStorage.DeleteEnvironment counted an environment's active secrets and then
// soft-deleted the environment in a separate statement, while RestoreProject took neither
// EnvironmentSecretGuardLockKey nor a lock on the environment row. On a LIVE environment
// that a restore had just revived under a deleted project, the count could run before the
// restore committed (zero: the secrets were still deleted) and the UPDATE after it,
// deleting an environment that now held active secrets.
//
// The test calls storage DeleteEnvironment directly (the API cannot reach it today: the
// scope middleware looks the environment up with the default scope first) and forces the
// interleaving with a gorm callback on pool A that parks DeleteEnvironment between its
// count and its UPDATE until pool B's RestoreProject has committed. With the environment
// row locked before the count, B's restore cannot commit while A is parked, so the park
// times out and A's UPDATE then finds the row still deleted. The assertion is on the end
// state, which holds under every legal ordering: never (environment deleted AND an active
// secret inside it). pg-gated (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

// openPGPoolInSchema opens one more pool (its own connections) on an existing schema.
func openPGPoolInSchema(t *testing.T, dsn, schema string) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(postgres.Open(pgdsn.PGSearchPathDSN(dsn, schema)), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = sqlDB.Close() })
	return db
}

func TestDeleteEnvironment_CannotDeleteEnvironmentRevivedByConcurrentRestoreProject_Postgres(t *testing.T) {
	dsn := requirePostgresDSN(t)
	ctx := context.Background()

	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "delenv_vs_restore_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})

	poolA := openPGPoolInSchema(t, dsn, schema)
	require.NoError(t, poolA.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{}))
	poolB := openPGPoolInSchema(t, dsn, schema)
	lsA, lsB := NewLocalStorage(poolA), NewLocalStorage(poolB)

	proj, err := lsA.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := lsA.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := lsA.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: env.ID, Name: "s",
		IsSecret: true, Type: "text", Status: "active"})
	require.NoError(t, err)

	// The state the race starts from: a deleted project whose cascade swept the environment
	// and the secret (one shared stamp), so a restore will bring all three back.
	cascade := time.Now().UTC().Add(-time.Minute)
	require.NoError(t, poolA.Exec("UPDATE projects SET deleted_at = ? WHERE id = ?", cascade, proj.ID).Error)
	require.NoError(t, poolA.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", cascade, env.ID).Error)
	require.NoError(t, poolA.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", cascade, secret.ID).Error)

	// Park pool A's environment soft-delete (the UPDATE) until B's restore has committed, or
	// a bounded wait has passed. The wait is what lets one test be red before the fix and
	// green after it: with the row locked up front the restore cannot commit while A is
	// parked, so the wait expires instead of the test hanging.
	restored := make(chan struct{})
	parked := make(chan struct{})
	var parkOnce sync.Once
	require.NoError(t, poolA.Callback().Delete().Before("gorm:delete").Register("test:park_env_delete", func(tx *gorm.DB) {
		if tx.Statement.Table != "environments" {
			return
		}
		parkOnce.Do(func() {
			close(parked)
			select {
			case <-restored:
			case <-time.After(3 * time.Second):
			}
		})
	}))

	deleteErr := make(chan error, 1)
	go func() { deleteErr <- lsA.DeleteEnvironment(ctx, env.ID) }()

	// The count has run by the time the UPDATE is parked.
	select {
	case <-parked:
	case err := <-deleteErr:
		// DeleteEnvironment finished without reaching its UPDATE (e.g. the environment row
		// was already seen as gone): nothing to interleave, the end-state check below still runs.
		deleteErr <- err
	case <-time.After(10 * time.Second):
		t.Fatal("DeleteEnvironment never reached its environment UPDATE")
	}

	restoreDone := make(chan error, 1)
	go func() {
		_, _, err := lsB.RestoreProject(ctx, proj.ID)
		close(restored)
		restoreDone <- err
	}()

	delErr := <-deleteErr
	require.NoError(t, <-restoreDone, "RestoreProject must succeed whichever side wins")
	t.Logf("DeleteEnvironment returned: %v", delErr)

	var envDeleted, activeSecrets int64
	require.NoError(t, poolA.Unscoped().Model(&models.Environment{}).
		Where("id = ? AND deleted_at IS NOT NULL", env.ID).Count(&envDeleted).Error)
	require.NoError(t, poolA.Model(&models.SecretNode{}).
		Where("environment_id = ? AND status = 'active'", env.ID).Count(&activeSecrets).Error)
	require.False(t, envDeleted > 0 && activeSecrets > 0,
		"environment %d was soft-deleted while holding %d active secret(s): DeleteEnvironment's count and its UPDATE straddled RestoreProject's commit (#4287)",
		env.ID, activeSecrets)
}
