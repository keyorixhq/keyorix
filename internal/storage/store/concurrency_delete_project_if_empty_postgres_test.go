// concurrency_delete_project_if_empty_postgres_test.go — #2887: forced
// interleaving proving DeleteProjectIfEmpty must row-lock the project BEFORE
// counting its secrets, not merely before the delete cascade.
//
// The exploit trace (coordinator review of #2885): CreateSecret inserts its
// row and takes FOR SHARE on the project (tx.LockLiveProject, the
// write-then-check protocol lockLiveParent's own doc comment describes);
// DeleteProjectIfEmpty counts secrets and sees 0 (CreateSecret's insert is
// still uncommitted, so it's invisible under READ COMMITTED regardless of any
// lock); DeleteProjectIfEmpty's cascade then tries to row-lock the project and
// blocks, because CreateSecret still holds FOR SHARE; CreateSecret commits,
// reporting success to its own caller; the cascade's lock now acquires, and
// its secret sweep -- a FRESH query, run after CreateSecret's commit -- finds
// and soft-deletes the just-created secret as part of deleting the project.
// A non-force delete removes a project that, at the moment its caller was
// told "created", held a live secret.
//
// This can only be demonstrated on Postgres: the row lock it exploits a gap
// around is a no-op on SQLite (lockProjectRowForCascade, lockLiveParent), so
// a single-connection SQLite test cannot reach the contention at all.
package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete forces
// the exact interleaving above via two independent Postgres connections,
// synchronized with channels so the ordering is deterministic every run, not
// a scheduler-dependent flake.
func TestConcurrency_DeleteProjectIfEmpty_LockFirstPreventsOrphanedDelete(t *testing.T) {
	base := pgTestDSN(t)
	dsn := pgIsolatedSchemaDSN(t, base)

	setupDB := pgOpen(t, dsn)
	require.NoError(t, setupDB.AutoMigrate(
		&models.Project{}, &models.Environment{}, &models.SecretNode{},
		&models.ShareRecord{}, &models.DynamicSecretConfig{},
	))

	project := &models.Project{Name: "race-project"}
	require.NoError(t, setupDB.Create(project).Error)
	env := &models.Environment{ProjectID: project.ID, Name: "dev"}
	require.NoError(t, setupDB.Create(env).Error)

	// Connection A: CreateSecret's write-then-FOR-SHARE protocol, held open
	// (holding the FOR SHARE) until explicitly released.
	secretConnDB := pgOpen(t, dsn)
	secretHoldsShare := make(chan struct{})
	releaseSecret := make(chan struct{})
	secretTxErr := make(chan error, 1)
	var secretID uint

	go func() {
		secretTxErr <- secretConnDB.Transaction(func(tx *gorm.DB) error {
			txStore := &LocalStorage{db: tx}
			secret := &models.SecretNode{ProjectID: project.ID, EnvironmentID: env.ID, Name: "race-me", IsSecret: true}
			created, err := txStore.CreateSecret(context.Background(), secret)
			if err != nil {
				return fmt.Errorf("create secret: %w", err)
			}
			secretID = created.ID
			live, err := txStore.LockLiveProject(context.Background(), project.ID)
			if err != nil {
				return fmt.Errorf("lock live project: %w", err)
			}
			if !live {
				return fmt.Errorf("project deleted while secret was being created")
			}
			close(secretHoldsShare)
			<-releaseSecret
			return nil
		})
	}()

	select {
	case <-secretHoldsShare:
	case <-time.After(5 * time.Second):
		t.Fatal("secret transaction never reached its FOR SHARE hold")
	}

	// Connection B: DeleteProjectIfEmpty, racing the held FOR SHARE above.
	deleteConnDB := pgOpen(t, dsn)
	deleteLS := NewLocalStorage(deleteConnDB)
	type deleteResult struct {
		blocking int
		err      error
	}
	deleteDone := make(chan deleteResult, 1)
	go func() {
		blocking, err := deleteLS.DeleteProjectIfEmpty(context.Background(), project.ID)
		deleteDone <- deleteResult{blocking, err}
	}()

	// No clean signal exists for "now blocked on the project row lock" short
	// of reading pg_locks — a short, generous sleep is the accepted tradeoff
	// this package's sibling contention tests already make (see
	// postgres_contention_helpers_test.go's own callers). What matters for
	// correctness is the ORDER of the two close() calls below, not this delay's
	// exact length: DeleteProjectIfEmpty is released to proceed only AFTER the
	// secret transaction commits, regardless of how long this wait is.
	time.Sleep(300 * time.Millisecond)
	close(releaseSecret)

	require.NoError(t, <-secretTxErr, "the secret transaction must commit cleanly -- the project was genuinely live when it checked")

	result := <-deleteDone
	require.NoError(t, result.err)

	// The fix: DeleteProjectIfEmpty's own project-row lock is taken BEFORE its
	// count, so once the secret transaction's commit releases the FOR SHARE
	// this blocked on, the count that follows correctly sees the now-committed
	// secret and refuses to delete the project.
	assert.Equal(t, 1, result.blocking,
		"DeleteProjectIfEmpty must see the secret CreateSecret committed during the race and refuse, not silently proceed on a stale zero count")

	var afterProject models.Project
	require.NoError(t, setupDB.Where("id = ?", project.ID).First(&afterProject).Error,
		"the project must survive -- it was never genuinely empty at the moment of decision")

	var afterSecret models.SecretNode
	require.NoError(t, setupDB.Where("id = ? AND deleted_at IS NULL", secretID).First(&afterSecret).Error,
		"the secret CreateSecret reported as successfully created must still be live, not silently swept by a cascade that ran moments later")
}
