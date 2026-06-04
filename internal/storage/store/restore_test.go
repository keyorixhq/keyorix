package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRestoreTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}))
	return NewLocalStorage(db)
}

func TestRestoreProjectCascade(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)

	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app", Description: "d"})
	require.NoError(t, err)
	_, err = ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: proj.ID})
	require.NoError(t, err)
	_, err = ls.CreateSecret(ctx, &models.SecretNode{
		ProjectID: proj.ID, EnvironmentID: 1, Name: "db-pw", IsSecret: true, Type: "text", Status: "active",
	})
	require.NoError(t, err)

	// Soft-delete the project (cascades to envs + secrets).
	require.NoError(t, ls.DeleteProject(ctx, proj.ID))

	// Default list excludes the deleted project; include_deleted surfaces it.
	active, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	assert.Empty(t, active, "soft-deleted project must not appear by default")

	all, err := ls.ListProjectsWithCounts(ctx, true)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.True(t, all[0].Deleted)
	assert.NotEmpty(t, all[0].DeletedAt)

	// Restore brings back the project and its environments. Secrets are NOT
	// restored — DeleteProject hard-deletes them (no soft-delete on SecretNode).
	require.NoError(t, ls.RestoreProject(ctx, proj.ID))

	restored, err := ls.ListProjectsWithCounts(ctx, false)
	require.NoError(t, err)
	require.Len(t, restored, 1)
	assert.False(t, restored[0].Deleted)
	assert.Equal(t, int64(0), restored[0].SecretCount, "secrets are hard-deleted, not restored")
	assert.Equal(t, int64(1), restored[0].EnvironmentCount, "environment should be restored")

	envs, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, envs, 1)
}

func TestRestoreProjectNotDeleted(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)

	// Restoring a project that isn't deleted is a no-op error.
	err = ls.RestoreProject(ctx, proj.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not deleted")
}

func TestRestoreEnvironment(t *testing.T) {
	ctx := context.Background()
	ls := newRestoreTestStore(t)
	proj, err := ls.CreateProject(ctx, &models.Project{Name: "app"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: proj.ID})
	require.NoError(t, err)

	require.NoError(t, ls.DeleteEnvironment(ctx, env.ID))

	// Excluded from the normal list, present in the include-deleted list.
	live, err := ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Empty(t, live)

	withDeleted, err := ls.ListEnvironmentsByProjectIncludingDeleted(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, withDeleted, 1)

	require.NoError(t, ls.RestoreEnvironment(ctx, env.ID))
	live, err = ls.ListEnvironmentsByProject(ctx, proj.ID)
	require.NoError(t, err)
	assert.Len(t, live, 1)

	// Restoring a live environment errors.
	err = ls.RestoreEnvironment(ctx, env.ID)
	require.Error(t, err)
}
