package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newVersionCommentsCore(store *MockStorage) *KeyorixCore {
	return &KeyorixCore{storage: store}
}

func TestCreateSecretVersionComment_EmptyCommentReturnsError(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	_, err := c.CreateSecretVersionComment(ctx, CreateVersionCommentRequest{
		SecretID:  1,
		VersionID: 2,
		Comment:   "",
		UserID:    10,
		Username:  "alice",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "comment is required")
	store.AssertNotCalled(t, "CreateSecretVersionComment")
}

func TestCreateSecretVersionComment_Success(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("CreateSecretVersionComment", ctx, mock.MatchedBy(func(cm *models.SecretVersionComment) bool {
		return cm.SecretID == 1 &&
			cm.VersionID == 2 &&
			cm.UserID == 10 &&
			cm.Username == "alice" &&
			cm.Comment == "bumped to rotate key"
	})).Return(nil)

	got, err := c.CreateSecretVersionComment(ctx, CreateVersionCommentRequest{
		SecretID:  1,
		VersionID: 2,
		Comment:   "bumped to rotate key",
		UserID:    10,
		Username:  "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, "bumped to rotate key", got.Comment)
	assert.Equal(t, uint(10), got.UserID)
}

func TestCreateSecretVersionComment_StorageError(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("CreateSecretVersionComment", ctx, mock.AnythingOfType("*models.SecretVersionComment")).
		Return(errors.New("write failed"))

	_, err := c.CreateSecretVersionComment(ctx, CreateVersionCommentRequest{
		SecretID: 1, VersionID: 2, Comment: "test", UserID: 1, Username: "u",
	})
	require.Error(t, err)
}

func TestListSecretVersionComments_Success(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	comments := []models.SecretVersionComment{
		{ID: 1, VersionID: 2, Comment: "initial version", UserID: 10, Username: "alice"},
		{ID: 2, VersionID: 2, Comment: "patched CVE-2026-001", UserID: 11, Username: "bob"},
	}
	store.On("ListSecretVersionComments", ctx, uint(2)).Return(comments, nil)

	got, err := c.ListSecretVersionComments(ctx, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "initial version", got[0].Comment)
	assert.Equal(t, "patched CVE-2026-001", got[1].Comment)
}

func TestListSecretVersionComments_Empty(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("ListSecretVersionComments", ctx, uint(5)).Return([]models.SecretVersionComment{}, nil)

	got, err := c.ListSecretVersionComments(ctx, 5)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSecretVersionComments_Error(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("ListSecretVersionComments", ctx, uint(3)).Return(nil, errors.New("read error"))

	_, err := c.ListSecretVersionComments(ctx, 3)
	require.Error(t, err)
}

func TestDeleteSecretVersionComment_Success(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("DeleteSecretVersionComment", ctx, uint(7)).Return(nil)

	err := c.DeleteSecretVersionComment(ctx, 7)
	require.NoError(t, err)
}

func TestDeleteSecretVersionComment_Error(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("DeleteSecretVersionComment", ctx, uint(8)).Return(errors.New("delete failed"))

	err := c.DeleteSecretVersionComment(ctx, 8)
	require.Error(t, err)
}
