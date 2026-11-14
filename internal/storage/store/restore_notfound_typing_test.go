package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RestoreProject answers ErrProjectNotFound only for a definitive not-found
// (INV-STORE-notfound-is-a-typed-sentinel): an absent project and a live one are
// not-found, but a fault on the row-lock read is a fault and never matches the sentinel.
func TestRestoreProject_NotFoundSentinelIsDefinitiveOnly(t *testing.T) {
	ctx := context.Background()

	t.Run("absent project is not found", func(t *testing.T) {
		ls := newRestoreTestStore(t)
		_, _, err := ls.RestoreProject(ctx, 9999)
		require.ErrorIs(t, err, storage.ErrProjectNotFound)
	})

	t.Run("live project is not found", func(t *testing.T) {
		ls := newRestoreTestStore(t)
		p, err := ls.CreateProject(ctx, &models.Project{Name: "live"})
		require.NoError(t, err)
		_, _, err = ls.RestoreProject(ctx, p.ID)
		require.ErrorIs(t, err, storage.ErrProjectNotFound)
	})

	t.Run("a fault on the lock read is not a not-found", func(t *testing.T) {
		ls := newRestoreTestStore(t)
		p, err := ls.CreateProject(ctx, &models.Project{Name: "gone"})
		require.NoError(t, err)
		require.NoError(t, ls.DeleteProject(ctx, p.ID))

		injected := errors.New("injected fault")
		require.NoError(t, ls.db.Callback().Query().Before("gorm:query").Register("test:restore-lock-fault", func(tx *gorm.DB) {
			if tx.Statement.Table == "projects" {
				_ = tx.AddError(injected)
			}
		}))

		_, _, err = ls.RestoreProject(ctx, p.ID)
		require.Error(t, err)
		assert.NotErrorIs(t, err, storage.ErrProjectNotFound, "a storage fault must not read as an absent project")
		assert.ErrorIs(t, err, injected, "the cause is kept")
	})
}

// requireLiveEnvironment (through RestoreSecret) answers not-found for an environment
// id that never existed, and "parent deleted" only for one that was soft-deleted: the
// twin of requireLiveProject.
func TestRestoreSecret_EnvironmentNeverExistedIsNotFound(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "env-twin"})
	require.NoError(t, err)

	// A secret pointing at an environment id that was never created.
	orphan := &models.SecretNode{ProjectID: p.ID, EnvironmentID: 777, Name: "orphan", IsSecret: true, Type: "text", Status: "active"}
	require.NoError(t, ls.db.Create(orphan).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UTC(), orphan.ID).Error)

	err = ls.RestoreSecret(ctx, orphan.ID)
	require.ErrorIs(t, err, storage.ErrEnvironmentNotFound)
	assert.NotErrorIs(t, err, storage.ErrParentDeleted)

	// A soft-deleted environment is still a deleted parent.
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)
	inEnv := &models.SecretNode{ProjectID: p.ID, EnvironmentID: env.ID, Name: "in-env", IsSecret: true, Type: "text", Status: "active"}
	require.NoError(t, ls.db.Create(inEnv).Error)
	require.NoError(t, ls.db.Exec("UPDATE secret_nodes SET deleted_at = ? WHERE id = ?", time.Now().Add(-time.Hour).UTC(), inEnv.ID).Error)
	require.NoError(t, ls.db.Exec("UPDATE environments SET deleted_at = ? WHERE id = ?", time.Now().UTC(), env.ID).Error)

	err = ls.RestoreSecret(ctx, inEnv.ID)
	require.ErrorIs(t, err, storage.ErrParentDeleted)
}
