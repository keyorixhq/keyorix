// named_lock_overlap_environment_postgres_test.go — NAMEDLOCK-OVERLAP-2, the
// PostgreSQL half of named_lock_overlap_environment_test.go: both write
// transactions open at once (overlapPGRun). RestoreSecret is the case only this
// test can tell apart: its transaction already re-checked the environment
// before NAMEDLOCK-OVERLAP-2 (requireLiveEnvironment through tx), but without a
// lock both transactions saw the environment live / zero active secrets.
package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/internal/testutil/pgdsn"
)

func TestNamedLockOverlap_EnvironmentSecretGuard_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	base := pgTestDSN(t)
	envState := func(t *testing.T, db *gorm.DB, envID uint) (envLive bool, active int64) {
		var envs int64
		require.NoError(t, db.Model(&models.Environment{}).Where("id = ?", envID).Count(&envs).Error)
		require.NoError(t, db.Model(&models.SecretNode{}).Where("environment_id = ? AND status = 'active'", envID).Count(&active).Error)
		return envs == 1, active
	}
	newSecret := func(projectID, envID uint) *CreateSecretRequest {
		return &CreateSecretRequest{Name: "s", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID, Type: "generic", CreatedBy: "test"}
	}
	cases := []struct {
		name string
		// deleteFirst: A deletes the environment and B creates; otherwise A
		// creates/restores and B deletes.
		deleteFirst bool
		setup       func(t *testing.T, c *KeyorixCore, projectID, envID uint) uint
		hookAt      func(start func()) *storagetest.StoreHooks
		actA        func(ctx context.Context, c *KeyorixCore, projectID, envID, secretID uint) error
	}{
		{name: "CreateSecret", hookAt: func(start func()) *storagetest.StoreHooks {
			return &storagetest.StoreHooks{CreateSecret: func(next storage.Storage, ctx context.Context, s *models.SecretNode, v ...string) (*models.SecretNode, error) {
				start()
				return next.CreateSecret(ctx, s, v...)
			}}
		}, actA: func(ctx context.Context, c *KeyorixCore, projectID, envID, _ uint) error {
			_, err := c.CreateSecret(ctx, newSecret(projectID, envID))
			return err
		}},
		{name: "RestoreSecret", setup: func(t *testing.T, c *KeyorixCore, projectID, envID uint) uint {
			s, err := c.CreateSecret(context.Background(), newSecret(projectID, envID))
			require.NoError(t, err)
			require.NoError(t, c.DeleteSecret(context.Background(), s.ID))
			return s.ID
		}, hookAt: func(start func()) *storagetest.StoreHooks {
			return &storagetest.StoreHooks{RestoreSecret: func(next storage.Storage, ctx context.Context, id uint) error {
				start()
				return next.RestoreSecret(ctx, id)
			}}
		}, actA: func(ctx context.Context, c *KeyorixCore, _, _, secretID uint) error {
			return c.RestoreSecret(ctx, 0, secretID)
		}},
		{name: "DeleteEnvironment", deleteFirst: true, hookAt: func(start func()) *storagetest.StoreHooks {
			return &storagetest.StoreHooks{DeleteEnvironment: func(next storage.Storage, ctx context.Context, id uint) error {
				start()
				return next.DeleteEnvironment(ctx, id)
			}}
		}, actA: func(ctx context.Context, c *KeyorixCore, _, envID, _ uint) error {
			return c.DeleteEnvironment(ctx, envID)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dsn := pgMigratedDatabaseDSN(t, base)
			admin := pgOpen(t, dsn)
			proj := &models.Project{Name: "proj"}
			require.NoError(t, admin.Create(proj).Error)
			env := &models.Environment{Name: "prod", ProjectID: proj.ID}
			require.NoError(t, admin.Create(env).Error)
			var secretID uint
			if tc.setup != nil {
				secretID = tc.setup(t, NewKeyorixCore(localstore.NewLocalStorage(admin)), proj.ID, env.ID)
			}

			errA, errB, early := overlapPGRun(t, dsn, tc.hookAt, func(ctx context.Context, c *KeyorixCore) error {
				return tc.actA(ctx, c, proj.ID, env.ID, secretID)
			}, func(ctx context.Context, c *KeyorixCore) error {
				if tc.deleteFirst {
					_, err := c.CreateSecret(ctx, newSecret(proj.ID, env.ID))
					return err
				}
				return c.DeleteEnvironment(ctx, env.ID)
			})

			envLive, active := envState(t, admin, env.ID)
			require.NoError(t, errA, "replica A held the environment's transaction key first and must win")
			require.False(t, early, "replica B's write transaction must wait for A's (it finished while A's was open: %v)", errB)
			require.False(t, !envLive && active > 0, "an active secret was left in a deleted environment (A: %v, B: %v)", errA, errB)
			// The refusal of B's own in-transaction check, run after A's commit
			// (never a timeout: B must have waited for A's transaction, not for a
			// lock A's section never releases).
			if tc.deleteFirst {
				require.ErrorContains(t, errB, "not found", "replica B's create finds the environment A deleted")
			} else {
				require.ErrorContains(t, errB, "active secret", "replica B's delete counts the secret A made active")
			}
		})
	}
}

// The race itself, for the restore: both replicas' named locks are lost (each
// takes its lock sessions in its own other database), and a restore of a
// soft-deleted secret races the deletion of its environment, many trials. No
// trial may leave the secret active in the deleted environment.
func TestNamedLockOverlap_RestoreSecretVsDeleteEnvironment_LostLocksRace_Postgres(t *testing.T) {
	t.Parallel()
	base := pgTestDSN(t)
	lostLockCore := func(db *gorm.DB) *KeyorixCore {
		lockDB, err := pgOpen(t, pgdsn.IsolatedDatabase(t, base, "overlap_lost_lock")).DB()
		require.NoError(t, err)
		ls := localstore.NewLocalStorage(db)
		ls.SetNamedLockDB(lockDB)
		return NewKeyorixCore(ls)
	}
	dsn := pgMigratedDatabaseDSN(t, base)
	admin := pgOpen(t, dsn)
	setup := NewKeyorixCore(localstore.NewLocalStorage(admin))
	replicaA, replicaB := lostLockCore(pgOpen(t, dsn)), lostLockCore(pgOpen(t, dsn))
	const trials = 150 // the restore's window is a few statements wide: 1 in 40 hit it on the pre-fix tree
	orphans := 0
	for i := range trials {
		proj := &models.Project{Name: fmt.Sprintf("race-%d", i)}
		require.NoError(t, admin.Create(proj).Error)
		env := &models.Environment{Name: "prod", ProjectID: proj.ID}
		require.NoError(t, admin.Create(env).Error)
		s, err := setup.CreateSecret(context.Background(), &CreateSecretRequest{Name: "s", Value: []byte("v"), ProjectID: proj.ID, EnvironmentID: env.ID, Type: "generic", CreatedBy: "test"})
		require.NoError(t, err)
		require.NoError(t, setup.DeleteSecret(context.Background(), s.ID))
		raceReplicas(t, func() error {
			return replicaA.RestoreSecret(context.Background(), 0, s.ID)
		}, func() error {
			return replicaB.DeleteEnvironment(context.Background(), env.ID)
		})
		var envs, active int64
		require.NoError(t, admin.Model(&models.Environment{}).Where("id = ?", env.ID).Count(&envs).Error)
		require.NoError(t, admin.Model(&models.SecretNode{}).Where("environment_id = ? AND status = 'active'", env.ID).Count(&active).Error)
		if envs == 0 && active > 0 {
			orphans++
		}
	}
	require.Zero(t, orphans, "%d/%d trials left a restored secret active in a deleted environment", orphans, trials)
}
