package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func newVersionCommentStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretVersionComment{}))
	return NewLocalStorage(db)
}

func TestSecretVersionComment_CreateListDelete(t *testing.T) {
	ls := newVersionCommentStore(t)
	ctx := context.Background()

	require.NoError(t, ls.CreateSecretVersionComment(ctx, &models.SecretVersionComment{
		SecretID: 1, VersionID: 10, UserID: 5, Username: "alice", Comment: "rotated for compliance",
	}))
	require.NoError(t, ls.CreateSecretVersionComment(ctx, &models.SecretVersionComment{
		SecretID: 1, VersionID: 10, UserID: 6, Username: "bob", Comment: "confirmed",
	}))
	// Different version on the same secret -- must not show up in a VersionID=10 listing.
	require.NoError(t, ls.CreateSecretVersionComment(ctx, &models.SecretVersionComment{
		SecretID: 1, VersionID: 11, UserID: 5, Username: "alice", Comment: "other version",
	}))
	// Same VersionID, different secret (#G53 cross-tenant guard) -- must not leak in.
	require.NoError(t, ls.CreateSecretVersionComment(ctx, &models.SecretVersionComment{
		SecretID: 2, VersionID: 10, UserID: 5, Username: "alice", Comment: "different secret",
	}))

	comments, err := ls.ListSecretVersionComments(ctx, 1, 10)
	require.NoError(t, err)
	require.Len(t, comments, 2)
	assert.Equal(t, "alice", comments[0].Username)
	assert.Equal(t, "bob", comments[1].Username)

	require.NoError(t, ls.DeleteSecretVersionComment(ctx, 1, 10, comments[0].ID))
	comments, err = ls.ListSecretVersionComments(ctx, 1, 10)
	require.NoError(t, err)
	require.Len(t, comments, 1)
	assert.Equal(t, "bob", comments[0].Username)
}

func TestSecretVersionComment_ListEmpty(t *testing.T) {
	ls := newVersionCommentStore(t)
	comments, err := ls.ListSecretVersionComments(context.Background(), 404, 404)
	require.NoError(t, err)
	assert.Empty(t, comments)
}

// A delete whose (secretID, versionID) doesn't match the comment's actual
// parent must fail, not silently delete the wrong row's owner check (#G53).
func TestSecretVersionComment_DeleteWrongParentFails(t *testing.T) {
	ls := newVersionCommentStore(t)
	ctx := context.Background()

	c := &models.SecretVersionComment{SecretID: 1, VersionID: 10, UserID: 5, Username: "alice", Comment: "x"}
	require.NoError(t, ls.CreateSecretVersionComment(ctx, c))

	err := ls.DeleteSecretVersionComment(ctx, 999, 10, c.ID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// The comment must still be there.
	comments, err := ls.ListSecretVersionComments(ctx, 1, 10)
	require.NoError(t, err)
	require.Len(t, comments, 1)
}

func TestSecretVersionComment_DeleteMissingFails(t *testing.T) {
	ls := newVersionCommentStore(t)
	err := ls.DeleteSecretVersionComment(context.Background(), 1, 10, 9999)
	require.Error(t, err)
}
