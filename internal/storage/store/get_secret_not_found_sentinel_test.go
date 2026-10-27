package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ERRLOSS-ACL-1 item 4: GetSecret wraps ErrSecretNotFound for a missing node, a
// leaf secret or a folder alike (GrantSecretACL's requireSecretOrFolderNode accepts
// both), and never for a storage failure.
func TestGetSecret_MissingNodeWrapsSentinel(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	ctx := context.Background()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}))
	ls := NewLocalStorage(db)

	_, err = ls.GetSecret(ctx, 4242)
	require.Error(t, err)
	assert.True(t, storage.IsSecretNotFound(err), "GetSecret(missing id) must wrap ErrSecretNotFound: %v", err)
	assert.Contains(t, err.Error(), i18n.T("ErrorSecretNotFound", nil))

	folder := &models.SecretNode{ProjectID: 1, EnvironmentID: 1, Name: "f", IsSecret: false, Type: "folder", Status: "active"}
	require.NoError(t, db.Create(folder).Error)
	_, err = ls.GetSecret(ctx, folder.ID)
	require.NoError(t, err, "a live folder node resolves")
	require.NoError(t, db.Delete(&models.SecretNode{}, folder.ID).Error)
	_, err = ls.GetSecret(ctx, folder.ID)
	require.Error(t, err)
	assert.True(t, storage.IsSecretNotFound(err), "GetSecret(deleted folder) must wrap ErrSecretNotFound: %v", err)
}

func TestGetSecret_StorageFailureIsNotSentinel(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db) // unmigrated: "no such table"

	_, err = ls.GetSecret(context.Background(), 1)
	require.Error(t, err)
	assert.False(t, storage.IsSecretNotFound(err), "storage failure must not be ErrSecretNotFound: %v", err)
}
