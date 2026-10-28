// named_lock_overlap_environment_test.go — NAMEDLOCK-OVERLAP-2, family
// "environment secret guard" (docs/design/named-lock-overlap.md; was NEEDS
// ANDREI, closed with LockNamedKeyInTx): every write that can make a secret
// node active in an environment takes EnvironmentSecretGuardLockKey with
// LockNamedKeyInTx in its write transaction and re-checks the environment
// through tx, and DeleteEnvironment takes the same key before it counts, so
// losing the named lock mid-section cannot leave an active secret in a deleted
// environment.
//
// Each case: holder A makes a secret node active in the environment; its lock
// is lost after its existence check passed, holder B (another replica) deletes
// the environment (no active secret yet) and commits, then A writes. A must be
// refused.
package core_test

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	kxstorage "github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newOverlapEnvironmentFixture: the full schema, one project and one
// environment.
func newOverlapEnvironmentFixture(t *testing.T) (db *gorm.DB, projectID, envID uint) {
	t.Helper()
	dsn := "file:" + filepath.Join(t.TempDir(), "overlap_env.db") + "?_busy_timeout=10000&_journal_mode=WAL&_txlock=immediate"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, kxstorage.MigrateExisting(db))
	proj := &models.Project{Name: "proj"}
	require.NoError(t, db.Create(proj).Error)
	env := &models.Environment{Name: "prod", ProjectID: proj.ID}
	require.NoError(t, db.Create(env).Error)
	return db, proj.ID, env.ID
}

// activeOrphan reports whether envID is deleted while an active secret node
// still references it.
func activeOrphan(t *testing.T, db *gorm.DB, envID uint) bool {
	t.Helper()
	var envs, nodes int64
	require.NoError(t, db.Model(&models.Environment{}).Where("id = ?", envID).Count(&envs).Error)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("environment_id = ? AND status = 'active'", envID).Count(&nodes).Error)
	return envs == 0 && nodes > 0
}

func TestNamedLockOverlap_EnvironmentSecretGuard_NoActiveSecretInDeletedEnvironment(t *testing.T) {
	t.Parallel()
	createSecret := func(ctx context.Context, c *core.KeyorixCore, projectID, envID uint) (uint, error) {
		s, err := c.CreateSecret(ctx, &core.CreateSecretRequest{Name: "s", Value: []byte("v"), ProjectID: projectID, EnvironmentID: envID, Type: "generic", CreatedBy: "test"})
		if err != nil {
			return 0, err
		}
		return s.ID, nil
	}
	cases := []struct {
		name string
		// setup prepares the environment through a plain core and returns the
		// secret A acts on (0 if none).
		setup func(t *testing.T, c *core.KeyorixCore, projectID, envID uint) uint
		act   func(ctx context.Context, c *core.KeyorixCore, projectID, envID, secretID uint) error
	}{
		{"CreateSecret", nil, func(ctx context.Context, c *core.KeyorixCore, projectID, envID, _ uint) error {
			_, err := createSecret(ctx, c, projectID, envID)
			return err
		}},
		{"CreateFolder", nil, func(ctx context.Context, c *core.KeyorixCore, projectID, envID, _ uint) error {
			_, err := c.CreateFolder(ctx, 0, "folder", projectID, envID, nil)
			return err
		}},
		{"RestoreSecret", func(t *testing.T, c *core.KeyorixCore, projectID, envID uint) uint {
			id, err := createSecret(context.Background(), c, projectID, envID)
			require.NoError(t, err)
			require.NoError(t, c.DeleteSecret(context.Background(), id))
			return id
		}, func(ctx context.Context, c *core.KeyorixCore, _, _, secretID uint) error {
			return c.RestoreSecret(ctx, 0, secretID)
		}},
		{"ResumeSecret", func(t *testing.T, c *core.KeyorixCore, projectID, envID uint) uint {
			id, err := createSecret(context.Background(), c, projectID, envID)
			require.NoError(t, err)
			_, err = c.SuspendSecret(context.Background(), id, 0, "hold")
			require.NoError(t, err)
			return id
		}, func(ctx context.Context, c *core.KeyorixCore, _, _, secretID uint) error {
			_, err := c.ResumeSecret(ctx, secretID, 0)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			db, projectID, envID := newOverlapEnvironmentFixture(t)
			replicaB := core.NewKeyorixCore(store.NewLocalStorage(db))
			var secretID uint
			if tc.setup != nil {
				secretID = tc.setup(t, replicaB, projectID, envID)
			}
			overlap := newLockLossOverlap(t, fmt.Sprintf("environment-secret-guard:%d", envID), func(ctx context.Context) error {
				return replicaB.DeleteEnvironment(ctx, envID)
			})
			replicaA := core.NewKeyorixCore(overlap.store(store.NewLocalStorage(db)))

			errA := tc.act(context.Background(), replicaA, projectID, envID, secretID)
			t.Logf("holder A: %v; holder B: %v", errA, overlap.secondErr)
			overlap.requireFired()

			require.NoError(t, overlap.secondErr, "holder B deleted an environment with no active secret and must succeed")
			require.False(t, activeOrphan(t, db, envID),
				"holder A made a secret active after holder B deleted its environment inside A's lost-lock window (A's error: %v)", errA)
			// "environment N not found" (withEnvironmentSecretGuard's re-check) or
			// "the parent environment is deleted" (the storage restore's own
			// requireLiveEnvironment, which runs through tx after the key).
			require.ErrorContains(t, errA, "environment", "A is refused by the in-transaction environment re-check")
		})
	}
}
