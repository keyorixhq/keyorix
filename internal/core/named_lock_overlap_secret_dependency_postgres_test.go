// named_lock_overlap_secret_dependency_postgres_test.go — NAMEDLOCK-OVERLAP-2,
// family "secret dependency graph" (docs/design/named-lock-overlap.md; was
// NEEDS ANDREI, closed with LockNamedKeyInTx): the edge insert runs in a
// transaction that first takes secretDependencyGraphLockKey with
// LockNamedKeyInTx, so two replicas whose named locks overlap cannot both pass
// the cycle check on a graph that lacks the other's edge.
//
// PostgreSQL only. The cycle check and the insert are one storage transaction
// (CreateSecretDependencyExclusive); on SQLite every write transaction is
// serialized (BEGIN IMMEDIATE, one process), so a second insert always reads
// the first one's committed edge and the overlap cannot produce a cycle there.
// On PostgreSQL it can: the check's FOR UPDATE locks only edges that exist, so
// on an empty graph (or for a new edge) neither transaction waits for the
// other, and both commit (#2660's phantom insert).
package core

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	localstore "github.com/keyorixhq/keyorix/internal/storage/store"
)

// seedDependencyGraphPG: a project with secrets x and y and no edges.
func seedDependencyGraphPG(t *testing.T, db *gorm.DB, name string) (proj, x, y uint) {
	t.Helper()
	p := models.Project{Name: name}
	require.NoError(t, db.Create(&p).Error)
	return p.ID, 1000*p.ID + 1, 1000*p.ID + 2
}

// edgesBetween counts the edges x->y and y->x.
func edgesBetween(t *testing.T, db *gorm.DB, x, y uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, db.Model(&models.SecretDependency{}).
		Where("(dependent_secret_id = ? AND depends_on_secret_id = ?) OR (dependent_secret_id = ? AND depends_on_secret_id = ?)", x, y, y, x).
		Count(&n).Error)
	return n
}

func newDependencyPGSchema(t *testing.T) string {
	t.Helper()
	dsn, setupDB := newPGLastAdminSchemaDSN(t)
	require.NoError(t, setupDB.AutoMigrate(&models.SecretDependency{}))
	closePG(setupDB)
	return dsn
}

// Deterministic: B adds y->x from inside A's write transaction, right before
// A's x->y insert. B must wait for A's transaction and then refuse the cycle.
func TestNamedLockOverlap_SecretDependency_ConcurrentWriteTransactions_Postgres(t *testing.T) {
	t.Parallel()
	dsn := newDependencyPGSchema(t)
	setupDB := pgOpen(t, dsn)
	proj, x, y := seedDependencyGraphPG(t, setupDB, "dep-overlap")
	closePG(setupDB)

	errA, errB, early := overlapPGRun(t, dsn, func(start func()) *storagetest.StoreHooks {
		return &storagetest.StoreHooks{CreateSecretDependencyExclusive: func(next storage.Storage, ctx context.Context, d *models.SecretDependency) (*models.SecretDependency, error) {
			start()
			return next.CreateSecretDependencyExclusive(ctx, d)
		}}
	}, func(ctx context.Context, c *KeyorixCore) error {
		_, err := c.LockedCreateSecretDependencyExclusive(ctx, &models.SecretDependency{ProjectID: proj, DependentSecretID: x, DependsOnSecretID: y})
		return err
	}, func(ctx context.Context, c *KeyorixCore) error {
		_, err := c.LockedCreateSecretDependencyExclusive(ctx, &models.SecretDependency{ProjectID: proj, DependentSecretID: y, DependsOnSecretID: x})
		return err
	})

	check := pgOpen(t, dsn)
	defer closePG(check)
	require.NoError(t, errA, "replica A held the graph's transaction key first and must win")
	require.False(t, early, "replica B's insert transaction must wait for A's (it finished while A's was open: %v)", errB)
	require.Equal(t, int64(1), edgesBetween(t, check, x, y), "two overlapping inserts committed a cycle (A: %v, B: %v)", errA, errB)
	require.ErrorIs(t, errB, storage.ErrSecretDependencyCycle, "replica B is refused by its cycle check, run after A's commit")
}

// The race itself: two replicas whose named locks are both lost add the two
// opposite edges at the same instant, on a fresh empty graph each trial. No
// trial may end with a cycle.
func TestNamedLockOverlap_SecretDependency_LostLocksRace_Postgres(t *testing.T) {
	t.Parallel()
	dsn := newDependencyPGSchema(t)
	lost := func(db *gorm.DB) *KeyorixCore {
		return NewKeyorixCore(storagetest.Hooked(localstore.NewLocalStorage(db), &storagetest.StoreHooks{
			WithNamedLock: func(_ storage.Storage, ctx context.Context, _ string, fn func(context.Context) error) error { return fn(ctx) },
		}))
	}
	dbA, dbB, setupDB := pgOpen(t, dsn), pgOpen(t, dsn), pgOpen(t, dsn)
	replicaA, replicaB := lost(dbA), lost(dbB)
	const trials = 40
	cycles := 0
	for i := range trials {
		proj, x, y := seedDependencyGraphPG(t, setupDB, fmt.Sprintf("dep-race-%d", i))
		res := raceReplicas(t, func() error {
			_, err := replicaA.LockedCreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{ProjectID: proj, DependentSecretID: x, DependsOnSecretID: y})
			return err
		}, func() error {
			_, err := replicaB.LockedCreateSecretDependencyExclusive(context.Background(), &models.SecretDependency{ProjectID: proj, DependentSecretID: y, DependsOnSecretID: x})
			return err
		})
		for _, err := range []error{res.ErrA, res.ErrB} {
			if err != nil && !errors.Is(err, storage.ErrSecretDependencyCycle) {
				t.Fatalf("trial %d: unexpected error (not a cycle refusal): %v", i, err)
			}
		}
		if edgesBetween(t, setupDB, x, y) == 2 {
			cycles++
		}
	}
	require.Zero(t, cycles, "%d/%d trials committed both opposite edges: a dependency cycle", cycles, trials)
}
