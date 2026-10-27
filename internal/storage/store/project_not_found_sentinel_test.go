package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// newProjectSentinelStore returns a LocalStorage whose schema is migrated only
// when migrate is true: an unmigrated store makes every lookup fail with a
// genuine storage error ("no such table"), never gorm.ErrRecordNotFound.
func newProjectSentinelStore(t *testing.T, migrate bool) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	if migrate {
		require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}))
	}
	return NewLocalStorage(db)
}

// ERRLOSS-MFA-1: a missing project/environment wraps the sentinel and keeps the
// exact legacy text, so existing text matchers keep working.
func TestGetProject_MissingRowWrapsSentinel(t *testing.T) {
	ctx := context.Background()
	ls := newProjectSentinelStore(t, true)

	_, err := ls.GetProject(ctx, 4242)
	require.Error(t, err)
	assert.True(t, storage.IsProjectNotFound(err), "GetProject(missing) must wrap ErrProjectNotFound: %v", err)
	assert.Equal(t, "project not found", err.Error())

	_, err = ls.GetProjectByName(ctx, "no-such-project")
	require.Error(t, err)
	assert.True(t, storage.IsProjectNotFound(err), "GetProjectByName(missing) must wrap ErrProjectNotFound: %v", err)
	assert.Equal(t, "project not found", err.Error())

	_, err = ls.GetEnvironment(ctx, 4242)
	require.Error(t, err)
	assert.True(t, storage.IsEnvironmentNotFound(err), "GetEnvironment(missing) must wrap ErrEnvironmentNotFound: %v", err)
	assert.Equal(t, "environment not found", err.Error())
}

// ERRLOSS-MFA-1: a genuine storage failure is never classified as "not found".
func TestGetProject_StorageFailureIsNotSentinel(t *testing.T) {
	ctx := context.Background()
	ls := newProjectSentinelStore(t, false)

	_, err := ls.GetProject(ctx, 1)
	require.Error(t, err)
	assert.False(t, storage.IsProjectNotFound(err), "storage failure must not be ErrProjectNotFound: %v", err)

	_, err = ls.GetProjectByName(ctx, "p")
	require.Error(t, err)
	assert.False(t, storage.IsProjectNotFound(err), "storage failure must not be ErrProjectNotFound: %v", err)

	_, err = ls.GetEnvironment(ctx, 1)
	require.Error(t, err)
	assert.False(t, storage.IsEnvironmentNotFound(err), "storage failure must not be ErrEnvironmentNotFound: %v", err)
}

func TestIsProjectNotFound_NilAndForeign(t *testing.T) {
	assert.False(t, storage.IsProjectNotFound(nil))
	assert.False(t, storage.IsEnvironmentNotFound(nil))
	assert.False(t, storage.IsProjectNotFound(storage.ErrEnvironmentNotFound))
	assert.False(t, storage.IsEnvironmentNotFound(storage.ErrProjectNotFound))
}
