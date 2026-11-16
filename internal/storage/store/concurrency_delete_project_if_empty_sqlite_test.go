// concurrency_delete_project_if_empty_sqlite_test.go — #2887, SQLite half.
//
// TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete (the
// Postgres file next to this one) forces the exact interleaving the bug needed.
// It cannot run on SQLite: there the row lock is a no-op and the guarantee
// comes from the production DSN's _txlock=immediate instead, which makes every
// write transaction take the single writer lock at BEGIN. Nothing on main
// asserted that this serialization still gives DeleteProjectIfEmpty the same
// outcome, so this test races real goroutines on independent connections
// (concurrentDB: a file database with the production DSN options) and checks
// the invariant that holds under every serial order:
//
//   - a secret whose creating transaction committed is live, and so is its
//     project (DeleteProjectIfEmpty saw it and refused), and
//   - a project DeleteProjectIfEmpty deleted has no committed secret: every
//     creator that ran after the delete saw the project gone and rolled back.
//
// The creators use CreateSecret's commit protocol (insert, then
// LockLiveProject in the same transaction), as the Postgres test does.
//
// What it does not prove: the #2887 fix itself. It also passes on the commit
// before that fix (9c1287e0c), because SQLite was never affected: the whole
// DeleteProjectIfEmpty transaction already held the writer lock before its
// count. It pins that premise, so a change that moves the count out of the
// delete's transaction is caught on the default CI dialect. It opens its own
// database with concurrentDB's copy of the production DSN options, so it does
// not notice a change to the production DSN (internal/storage) itself.
package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

var errProjectGoneDuringCreate = errors.New("project deleted while secret was being created")

func TestConcurrency_DeleteProjectIfEmpty_RacingCreatesNeverOrphaned_SQLite(t *testing.T) {
	db := concurrentDB(t)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.SecretACL{}, &models.AccessRequest{}, &models.DynamicSecretConfig{},
	))
	ctx := context.Background()

	const rounds = 20
	const creators = 4
	sawDelete, sawRefusal := 0, 0

	for round := range rounds {
		project := &models.Project{Name: fmt.Sprintf("race-project-%d", round)}
		require.NoError(t, db.Create(project).Error)
		env := &models.Environment{ProjectID: project.ID, Name: "dev"}
		require.NoError(t, db.Create(env).Error)

		start := make(chan struct{})
		var wg sync.WaitGroup
		createdIDs := make([]uint, creators)
		createErrs := make([]error, creators)
		for i := range creators {
			wg.Go(func() {
				<-start
				createErrs[i] = db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
					txStore := &LocalStorage{db: tx}
					created, err := txStore.CreateSecret(ctx, &models.SecretNode{
						ProjectID: project.ID, EnvironmentID: env.ID,
						Name: fmt.Sprintf("race-me-%d", i), IsSecret: true,
					})
					if err != nil {
						return fmt.Errorf("create secret: %w", err)
					}
					live, err := txStore.LockLiveProject(ctx, project.ID)
					if err != nil {
						return fmt.Errorf("lock live project: %w", err)
					}
					if !live {
						return errProjectGoneDuringCreate
					}
					createdIDs[i] = created.ID
					return nil
				})
			})
		}
		var blocking int
		var deleteErr error
		wg.Go(func() {
			<-start
			blocking, deleteErr = NewLocalStorage(db).DeleteProjectIfEmpty(ctx, project.ID)
		})
		close(start)
		wg.Wait()

		require.NoError(t, deleteErr, "round %d", round)
		committed := 0
		for i, err := range createErrs {
			if err != nil {
				require.ErrorIs(t, err, errProjectGoneDuringCreate,
					"round %d creator %d: the only legal create failure is seeing the project already deleted", round, i)
				continue
			}
			committed++
			var s models.SecretNode
			require.NoError(t, db.Where("id = ? AND deleted_at IS NULL", createdIDs[i]).First(&s).Error,
				"round %d creator %d: a secret whose create committed must stay live, not be swept by the delete", round, i)
		}

		var live int64
		require.NoError(t, db.Model(&models.Project{}).Where("id = ?", project.ID).Count(&live).Error)
		if blocking == 0 {
			sawDelete++
			assert.Zero(t, live, "round %d: DeleteProjectIfEmpty reported success, so the project is gone", round)
			assert.Zero(t, committed,
				"round %d: a deleted project must hold no committed secret; a creator that ran after the delete must have rolled back", round)
		} else {
			sawRefusal++
			assert.Equal(t, int64(1), live, "round %d: DeleteProjectIfEmpty refused, so the project survives", round)
			// Creators that ran after the refusal also commit (the project is
			// still live), so the refusal counted at most the committed ones.
			assert.LessOrEqual(t, blocking, committed,
				"round %d: the refusal can only count secrets whose creates committed", round)
		}
	}
	t.Logf("%d rounds: %d deletes won, %d refused on a racing secret", rounds, sawDelete, sawRefusal)
}
