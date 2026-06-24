package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSoftDeleteTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Environment{}))
	return NewLocalStorage(db)
}

func TestSecretSoftDeleteLifecycle(t *testing.T) {
	ls := newSoftDeleteTestStore(t)
	ctx := context.Background()
	const projectID = uint(1)

	require.NoError(t, ls.db.Create(&models.Environment{ID: 10, ProjectID: projectID, Name: "dev"}).Error)
	s, err := ls.CreateSecret(ctx, &models.SecretNode{ProjectID: projectID, EnvironmentID: 10, Name: "API_KEY", IsSecret: true, Type: "api_key", Status: "active"})
	require.NoError(t, err)

	// Soft-delete via the model-aware Delete (now a deleted_at stamp, not a row removal).
	require.NoError(t, ls.DeleteSecret(ctx, s.ID))

	// Scoped reads hide it; Unscoped read still finds it.
	_, err = ls.GetSecret(ctx, s.ID)
	require.Error(t, err, "GetSecret hides soft-deleted secrets")
	got, err := ls.GetSecretIncludingDeleted(ctx, s.ID)
	require.NoError(t, err)
	assert.True(t, got.DeletedAt.Valid, "row retained with deleted_at set")

	// ListSecrets excludes by default, includes with IncludeDeleted.
	live, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: ptr(projectID), Page: 1, PageSize: 50})
	require.NoError(t, err)
	assert.Len(t, live, 0, "soft-deleted secret excluded from default listing")
	all, _, err := ls.ListSecrets(ctx, &storage.SecretFilter{ProjectID: ptr(projectID), Page: 1, PageSize: 50, IncludeDeleted: true})
	require.NoError(t, err)
	assert.Len(t, all, 1, "IncludeDeleted surfaces it for the restore UI")

	// The drift raw query (Table/Joins) must also exclude it.
	drift, err := ls.ListProjectSecretsForDrift(ctx, projectID)
	require.NoError(t, err)
	assert.Len(t, drift, 0, "raw drift query filters s.deleted_at IS NULL")

	// Restore brings it back.
	require.NoError(t, ls.RestoreSecret(ctx, s.ID))
	restored, err := ls.GetSecret(ctx, s.ID)
	require.NoError(t, err)
	assert.Equal(t, "API_KEY", restored.Name)
}

func TestPurgeDeletedSecretsBefore(t *testing.T) {
	ls := newSoftDeleteTestStore(t)
	ctx := context.Background()

	// Two soft-deleted secrets, one 40d old, one 5d old (stamp deleted_at directly).
	for i, name := range []string{"old", "recent"} {
		require.NoError(t, ls.db.Create(&models.SecretNode{ID: uint(i + 1), ProjectID: 1, EnvironmentID: 10, Name: name, IsSecret: true}).Error)
	}
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where("name = ?", "old").Update("deleted_at", time.Now().AddDate(0, 0, -40)).Error)
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where("name = ?", "recent").Update("deleted_at", time.Now().AddDate(0, 0, -5)).Error)

	n, err := ls.PurgeDeletedSecretsBefore(ctx, time.Now().AddDate(0, 0, -30))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only the 40-day-old soft-deleted secret is purged")

	var remaining int64
	require.NoError(t, ls.db.Unscoped().Model(&models.SecretNode{}).Where("name = ?", "old").Count(&remaining).Error)
	assert.Equal(t, int64(0), remaining, "purged row hard-deleted")
}

func ptr[T any](v T) *T { return &v }
