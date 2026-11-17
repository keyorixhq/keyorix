package store

// STORE-LOCKS-NOV-1 item 1: the #4287 fix row-locks the environment (unscoped FOR UPDATE)
// inside DeleteEnvironment's transaction, under its EnvironmentSecretGuardLockKey.
// RestoreProject and DeleteProject both take the project row first, then UPDATE the
// environment and secret rows; neither takes the guard key. DeleteEnvironment's transaction locks only the one environment row
// (its count is a plain read), so no wait cycle exists. This test is the runtime check of
// that argument: DeleteEnvironment on both of a project's environments, RestoreProject and
// DeleteProject start together, each on its own pool (a replica), 200 times. Every call
// must end with nil or its documented refusal, never a deadlock (40P01) or a lock wait
// that outlives the iteration deadline, and each end state must hold the liveness
// invariants. pg-gated (KEYORIX_TEST_PG_DSN).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

const deleteEnvLockOrderIterations = 200

func TestDeleteEnvironment_RestoreProject_DeleteProject_NoDeadlock_Postgres(t *testing.T) {
	dsn := requirePostgresDSN(t)
	ctx := context.Background()

	var suffix [6]byte
	_, err := rand.Read(suffix[:])
	require.NoError(t, err)
	schema := "delenv_lock_order_" + hex.EncodeToString(suffix[:])
	admin, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	require.NoError(t, admin.Exec("CREATE SCHEMA "+schema).Error)
	t.Cleanup(func() {
		_ = admin.Exec("DROP SCHEMA IF EXISTS " + schema + " CASCADE").Error
		if a, e := admin.DB(); e == nil {
			_ = a.Close()
		}
	})

	seed := openPGPoolInSchema(t, dsn, schema)
	require.NoError(t, seed.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.ShareRecord{},
		&models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{}))
	seedLS := NewLocalStorage(seed)
	delEnvA := NewLocalStorage(openPGPoolInSchema(t, dsn, schema))
	delEnvB := NewLocalStorage(openPGPoolInSchema(t, dsn, schema))
	restorer := NewLocalStorage(openPGPoolInSchema(t, dsn, schema))
	deleter := NewLocalStorage(openPGPoolInSchema(t, dsn, schema))

	// outcomes counts each call's result, logged at the end so a run shows that the
	// orderings actually varied (a fixed winner would not exercise the locks).
	outcomes := map[string]int{}
	for i := range deleteEnvLockOrderIterations {
		// A project deleted by one cascade: "prod" held a secret, "dev" was empty.
		proj, err := seedLS.CreateProject(ctx, &models.Project{Name: fmt.Sprintf("app-%d", i)})
		require.NoError(t, err)
		prod, err := seedLS.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
		require.NoError(t, err)
		dev, err := seedLS.CreateEnvironment(ctx, &models.Environment{Name: "dev", ProjectID: proj.ID})
		require.NoError(t, err)
		_, err = seedLS.CreateSecret(ctx, &models.SecretNode{ProjectID: proj.ID, EnvironmentID: prod.ID, Name: "s",
			IsSecret: true, Type: "text", Status: "active"})
		require.NoError(t, err)
		require.NoError(t, seedLS.DeleteProject(ctx, proj.ID))

		iterCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 4)
		calls := []func() error{
			func() error { return delEnvA.DeleteEnvironment(iterCtx, prod.ID) },
			func() error { return delEnvB.DeleteEnvironment(iterCtx, dev.ID) },
			func() error { _, _, err := restorer.RestoreProject(iterCtx, proj.ID); return err },
			func() error { return deleter.DeleteProject(iterCtx, proj.ID) },
		}
		for k, call := range calls {
			wg.Go(func() {
				<-start
				// Up to 3 ms of jitter, so every call gets to go first in some iterations.
				time.Sleep(time.Duration(mathrand.IntN(3000)) * time.Microsecond)
				errs[k] = call()
			})
		}
		close(start)
		wg.Wait()
		cancel()

		for k, err := range errs {
			outcomes[fmt.Sprintf("call%d: %v", k, err)]++
			if err == nil {
				continue
			}
			allowed := errors.Is(err, storage.ErrEnvironmentNotFound) || errors.Is(err, storage.ErrEnvironmentHasSecrets)
			if k >= 2 {
				allowed = errors.Is(err, storage.ErrProjectNotFound)
			}
			require.Truef(t, allowed, "iteration %d call %d: unexpected error (deadlock, lock timeout or a new refusal): %v", i, k, err)
		}

		var projDeleted, liveEnvs, liveSecrets, activeInDeletedEnv int64
		require.NoError(t, seed.Unscoped().Model(&models.Project{}).
			Where("id = ? AND deleted_at IS NOT NULL", proj.ID).Count(&projDeleted).Error)
		require.NoError(t, seed.Model(&models.Environment{}).Where("project_id = ?", proj.ID).Count(&liveEnvs).Error)
		require.NoError(t, seed.Model(&models.SecretNode{}).Where("project_id = ?", proj.ID).Count(&liveSecrets).Error)
		require.NoError(t, seed.Raw(`SELECT COUNT(*) FROM secret_nodes s JOIN environments e ON e.id = s.environment_id
			WHERE e.project_id = ? AND e.deleted_at IS NOT NULL AND s.deleted_at IS NULL AND s.status = 'active'`, proj.ID).
			Scan(&activeInDeletedEnv).Error)
		require.Zerof(t, activeInDeletedEnv, "iteration %d: an environment was soft-deleted while holding an active secret", i)
		if projDeleted > 0 {
			require.Zerof(t, liveEnvs+liveSecrets, "iteration %d: the project is deleted but %d environment(s) and %d secret(s) under it are live",
				i, liveEnvs, liveSecrets)
		}
		require.NoErrorf(t, errs[2], "iteration %d: RestoreProject on a deleted project must succeed whichever call wins", i)
	}
	t.Logf("outcomes over %d iterations: %v", deleteEnvLockOrderIterations, outcomes)
}
