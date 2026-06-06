package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestListUserPermissions_IncludesGroupShares(t *testing.T) {
	ctx := context.Background()
	const userID = uint(7)
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	// Owned secret #1.
	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).
		Return([]*models.SecretNode{{ID: 1}}, int64(1), nil)
	// Direct share of secret #2.
	ms.On("ListSharesByUser", ctx, userID).
		Return([]*models.ShareRecord{{ID: 20, SecretID: 2, Permission: "read"}}, nil)
	// User belongs to group #5, which has secret #3 shared with write.
	ms.On("GetUserGroups", ctx, userID).
		Return([]*models.Group{{ID: 5, Name: "team"}}, nil)
	ms.On("ListSharesByGroup", ctx, uint(5)).
		Return([]*models.ShareRecord{{ID: 30, SecretID: 3, Permission: "write", IsGroup: true, RecipientID: 5}}, nil)

	perms, err := c.ListUserPermissions(ctx, userID)
	require.NoError(t, err)

	bySource := map[string]*models.UserSecretPermission{}
	for _, p := range perms {
		bySource[p.Source] = p
	}

	require.Contains(t, bySource, "owner")
	require.Contains(t, bySource, "direct_share")
	require.Contains(t, bySource, "group_share")

	g := bySource["group_share"]
	assert.Equal(t, uint(3), g.SecretID)
	assert.Equal(t, "write", g.Permission)
	require.NotNil(t, g.GroupID)
	assert.Equal(t, uint(5), *g.GroupID)
	require.NotNil(t, g.ShareID)
	assert.Equal(t, uint(30), *g.ShareID)
}

func TestListUserPermissions_NoGroups(t *testing.T) {
	ctx := context.Background()
	const userID = uint(8)
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).
		Return([]*models.SecretNode{}, int64(0), nil)
	ms.On("ListSharesByUser", ctx, userID).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", ctx, userID).Return([]*models.Group{}, nil)

	perms, err := c.ListUserPermissions(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, perms)
	ms.AssertNotCalled(t, "ListSharesByGroup", mock.Anything, mock.Anything)
}
