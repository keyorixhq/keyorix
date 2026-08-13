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

// expectSecretWithVersion wires up the GetSecret + GetSecretVersions calls
// versionBelongsToSecret makes, for a secret that owns versionID.
func expectSecretWithVersion(store *MockStorage, ctx context.Context, secretID, versionID uint) {
	store.On("GetSecret", ctx, secretID).Return(&models.SecretNode{ID: secretID}, nil)
	store.On("GetSecretVersions", ctx, secretID).
		Return([]*models.SecretVersion{{ID: versionID, SecretNodeID: secretID}}, nil)
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

	expectSecretWithVersion(store, ctx, 1, 2)
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

	expectSecretWithVersion(store, ctx, 1, 2)
	store.On("CreateSecretVersionComment", ctx, mock.AnythingOfType("*models.SecretVersionComment")).
		Return(errors.New("write failed"))

	_, err := c.CreateSecretVersionComment(ctx, CreateVersionCommentRequest{
		SecretID: 1, VersionID: 2, Comment: "test", UserID: 1, Username: "u",
	})
	require.Error(t, err)
}

// TestCreateSecretVersionComment_VersionBelongsToOtherSecret is the #G53
// regression: VersionID 99 belongs to secret 2, not the authorized secret 1 —
// the write must be refused before it ever reaches storage.
func TestCreateSecretVersionComment_VersionBelongsToOtherSecret(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	store.On("GetSecretVersions", ctx, uint(1)).
		Return([]*models.SecretVersion{{ID: 42, SecretNodeID: 1}}, nil)

	_, err := c.CreateSecretVersionComment(ctx, CreateVersionCommentRequest{
		SecretID: 1, VersionID: 99, Comment: "cross-tenant write", UserID: 1, Username: "attacker",
	})
	require.Error(t, err)
	store.AssertNotCalled(t, "CreateSecretVersionComment")
}

func TestListSecretVersionComments_Success(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	expectSecretWithVersion(store, ctx, 1, 2)
	comments := []models.SecretVersionComment{
		{ID: 1, SecretID: 1, VersionID: 2, Comment: "initial version", UserID: 10, Username: "alice"},
		{ID: 2, SecretID: 1, VersionID: 2, Comment: "patched CVE-2026-001", UserID: 11, Username: "bob"},
	}
	store.On("ListSecretVersionComments", ctx, uint(1), uint(2)).Return(comments, nil)

	got, err := c.ListSecretVersionComments(ctx, 1, 2)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "initial version", got[0].Comment)
	assert.Equal(t, "patched CVE-2026-001", got[1].Comment)
}

func TestListSecretVersionComments_Empty(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	expectSecretWithVersion(store, ctx, 5, 5)
	store.On("ListSecretVersionComments", ctx, uint(5), uint(5)).Return([]models.SecretVersionComment{}, nil)

	got, err := c.ListSecretVersionComments(ctx, 5, 5)
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestListSecretVersionComments_Error(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	expectSecretWithVersion(store, ctx, 3, 3)
	store.On("ListSecretVersionComments", ctx, uint(3), uint(3)).Return(nil, errors.New("read error"))

	_, err := c.ListSecretVersionComments(ctx, 3, 3)
	require.Error(t, err)
}

// TestListSecretVersionComments_CrossSecretVersionRejected is the #G53
// regression: authorized on secret 1, but the supplied VersionID (99) belongs
// to secret 2 — must be refused, not silently walk the global VersionID space.
func TestListSecretVersionComments_CrossSecretVersionRejected(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	store.On("GetSecretVersions", ctx, uint(1)).
		Return([]*models.SecretVersion{{ID: 7, SecretNodeID: 1}}, nil)

	_, err := c.ListSecretVersionComments(ctx, 1, 99)
	require.Error(t, err)
	store.AssertNotCalled(t, "ListSecretVersionComments")
}

func TestDeleteSecretVersionComment_Success(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	expectSecretWithVersion(store, ctx, 1, 2)
	store.On("DeleteSecretVersionComment", ctx, uint(1), uint(2), uint(7)).Return(nil)

	err := c.DeleteSecretVersionComment(ctx, 1, 2, 7)
	require.NoError(t, err)
}

func TestDeleteSecretVersionComment_Error(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	expectSecretWithVersion(store, ctx, 1, 2)
	store.On("DeleteSecretVersionComment", ctx, uint(1), uint(2), uint(8)).Return(errors.New("delete failed"))

	err := c.DeleteSecretVersionComment(ctx, 1, 2, 8)
	require.Error(t, err)
}

// TestDeleteSecretVersionComment_CrossSecretVersionRejected is the #G53
// regression for delete: authorized on secret 1, but the supplied VersionID
// belongs to secret 2 — must be refused before any storage delete is attempted.
func TestDeleteSecretVersionComment_CrossSecretVersionRejected(t *testing.T) {
	store := new(MockStorage)
	c := newVersionCommentsCore(store)
	ctx := context.Background()

	store.On("GetSecret", ctx, uint(1)).Return(&models.SecretNode{ID: 1}, nil)
	store.On("GetSecretVersions", ctx, uint(1)).
		Return([]*models.SecretVersion{{ID: 7, SecretNodeID: 1}}, nil)

	err := c.DeleteSecretVersionComment(ctx, 1, 99, 8)
	require.Error(t, err)
	store.AssertNotCalled(t, "DeleteSecretVersionComment")
}
