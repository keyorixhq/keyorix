package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
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

func TestListUserPermissions_ExcludesExpiredShares(t *testing.T) {
	ctx := context.Background()
	const userID = uint(9)
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	past := time.Now().Add(-1 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).
		Return([]*models.SecretNode{}, int64(0), nil)
	// One active direct share (#2) and one expired direct share (#3).
	ms.On("ListSharesByUser", ctx, userID).
		Return([]*models.ShareRecord{
			{ID: 20, SecretID: 2, Permission: "read"},
			{ID: 21, SecretID: 3, Permission: "read", ExpiresAt: &past},
		}, nil)
	// Group #5: one active group share (#4) and one expired (#5).
	ms.On("GetUserGroups", ctx, userID).Return([]*models.Group{{ID: 5}}, nil)
	ms.On("ListSharesByGroup", ctx, uint(5)).
		Return([]*models.ShareRecord{
			{ID: 30, SecretID: 4, Permission: "write", IsGroup: true, RecipientID: 5, ExpiresAt: &future},
			{ID: 31, SecretID: 5, Permission: "write", IsGroup: true, RecipientID: 5, ExpiresAt: &past},
		}, nil)

	perms, err := c.ListUserPermissions(ctx, userID)
	require.NoError(t, err)

	secrets := map[uint]bool{}
	for _, p := range perms {
		secrets[p.SecretID] = true
	}
	assert.True(t, secrets[2], "active direct share should be listed")
	assert.True(t, secrets[4], "non-expired group share should be listed")
	assert.False(t, secrets[3], "expired direct share must NOT be listed")
	assert.False(t, secrets[5], "expired group share must NOT be listed")
}

// TestListUserPermissions_PaginatesOwnedSecretsBeyondOnePage pins the fix for a user
// who owns more secrets than a single storage page: ListUserPermissions must walk
// every page of owned secrets rather than stopping after the first
// listUserPermissionsOwnedPageSize-sized page, or ownership beyond that page would be
// silently dropped from the listing.
func TestListUserPermissions_PaginatesOwnedSecretsBeyondOnePage(t *testing.T) {
	ctx := context.Background()
	const userID = uint(11)
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	// Page 1 is a full page (exactly the page size) with total > page size, so the
	// loop must keep going; page 2 returns the remainder.
	firstPage := make([]*models.SecretNode, listUserPermissionsOwnedPageSize)
	for i := range firstPage {
		firstPage[i] = &models.SecretNode{ID: uint(i + 1)}
	}
	total := int64(listUserPermissionsOwnedPageSize + 3)

	ms.On("ListSecrets", ctx, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.Page == 1 && f.PageSize == listUserPermissionsOwnedPageSize
	})).Return(firstPage, total, nil)
	ms.On("ListSecrets", ctx, mock.MatchedBy(func(f *storage.SecretFilter) bool {
		return f.Page == 2 && f.PageSize == listUserPermissionsOwnedPageSize
	})).Return([]*models.SecretNode{
		{ID: uint(listUserPermissionsOwnedPageSize + 1)},
		{ID: uint(listUserPermissionsOwnedPageSize + 2)},
		{ID: uint(listUserPermissionsOwnedPageSize + 3)},
	}, total, nil)
	ms.On("ListSharesByUser", ctx, userID).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", ctx, userID).Return([]*models.Group{}, nil)

	perms, err := c.ListUserPermissions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, perms, int(total), "every owned secret across both pages must be listed")
	ms.AssertNumberOfCalls(t, "ListSecrets", 2)
}

// TestListUserPermissions_ClockSteppedBackward_ExpiredShareStaysExcluded is the
// #1655 sibling to TestListSecretShares_ClockSteppedBackward_ExpiredShareStaysExcluded
// (share_clock_regression_test.go): ListUserPermissions was the 8th of 8 shareActive
// call sites left on a bare c.now() instead of the monotonic-watermark
// c.shareEffectiveNow(), so a share already expired relative to a time this process
// has previously observed could be resurrected by a real clock reading that looks
// earlier (a backward-stepped host clock, e.g. NTP correction or VM pause/resume).
func TestListUserPermissions_ClockSteppedBackward_ExpiredShareStaysExcluded(t *testing.T) {
	ctx := context.Background()
	const userID = uint(13)
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)

	future := time.Now().Add(24 * time.Hour)
	c.shareClockWatermark = future

	// Genuinely expired relative to the watermark, but NOT expired relative to the
	// real, un-mocked time.Now() this test actually runs at.
	expiry := time.Now().Add(time.Hour)

	ms.On("ListSecrets", ctx, mock.AnythingOfType("*storage.SecretFilter")).
		Return([]*models.SecretNode{}, int64(0), nil)
	ms.On("ListSharesByUser", ctx, userID).
		Return([]*models.ShareRecord{{ID: 20, SecretID: 2, Permission: "read", ExpiresAt: &expiry}}, nil)
	ms.On("GetUserGroups", ctx, userID).Return([]*models.Group{}, nil)

	perms, err := c.ListUserPermissions(ctx, userID)
	require.NoError(t, err)
	assert.Empty(t, perms, "a share already expired relative to a time this process has previously observed must not be resurrected by a real clock reading that looks earlier")
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
