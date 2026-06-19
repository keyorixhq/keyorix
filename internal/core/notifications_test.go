package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// allowNotifications registers a permissive expectation for the best-effort
// CreateNotification side effect, so tests exercising an action that now emits a
// notification don't fail on the extra storage call. (GetProject /
// ListProjectMembers are hard-coded stubs in MockStorage, so they need no
// expectation.) Shared across core tests.
func allowNotifications(store *MockStorage) {
	store.On("CreateNotification", mock.Anything, mock.Anything).
		Return(&models.Notification{ID: 1}, nil).Maybe()
}

func TestIsApproverRole(t *testing.T) {
	for _, r := range []string{"project_admin", "system_admin", "admin", "super_admin"} {
		assert.True(t, isApproverRole(r), r)
	}
	for _, r := range []string{"project_viewer", "project_developer", "system_viewer", ""} {
		assert.False(t, isApproverRole(r), r)
	}
}

func TestNotifyMembershipActivated(t *testing.T) {
	t.Run("notifies a distinct inviter with a project link", func(t *testing.T) {
		store := new(MockStorage)
		c := newMembershipCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return n.UserID == 9 && n.Type == NotificationMembershipActivated
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifyMembershipActivated(ctx, &models.ProjectMembership{ProjectID: 1, UserID: 2, InvitedBy: 9})
		store.AssertExpectations(t)
		require.NotNil(t, got)
		assert.Contains(t, got.Message, "active member")
		assert.Equal(t, "/projects/1", got.Link)
		require.NotNil(t, got.ProjectID)
		assert.Equal(t, uint(1), *got.ProjectID)
	})

	t.Run("skips a self-invite (inviter == member)", func(t *testing.T) {
		store := new(MockStorage)
		c := newMembershipCore(store)
		c.notifyMembershipActivated(context.Background(), &models.ProjectMembership{ProjectID: 1, UserID: 9, InvitedBy: 9})
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})

	t.Run("skips when there is no inviter", func(t *testing.T) {
		store := new(MockStorage)
		c := newMembershipCore(store)
		c.notifyMembershipActivated(context.Background(), &models.ProjectMembership{ProjectID: 1, UserID: 2, InvitedBy: 0})
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})
}

func TestNotifyAccessResolved_NotifiesRequester(t *testing.T) {
	t.Run("approved", func(t *testing.T) {
		store := new(MockStorage)
		c := newMembershipCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return true
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifyAccessResolved(ctx, &models.AccessRequest{ProjectID: 1, UserID: 2, GrantedRole: "project_developer"}, true)
		require.NotNil(t, got)
		assert.Equal(t, uint(2), got.UserID)
		assert.Equal(t, NotificationAccessApproved, got.Type)
		assert.Contains(t, got.Message, "project_developer")
	})

	t.Run("rejected", func(t *testing.T) {
		store := new(MockStorage)
		c := newMembershipCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return true
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifyAccessResolved(ctx, &models.AccessRequest{ProjectID: 1, UserID: 2}, false)
		require.NotNil(t, got)
		assert.Equal(t, uint(2), got.UserID)
		assert.Equal(t, NotificationAccessRejected, got.Type)
	})
}

func TestNotificationSelfScopedDelegations(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	store.On("ListNotifications", ctx, uint(2), true, 10).Return([]*models.Notification{{ID: 1}}, nil)
	store.On("CountUnreadNotifications", ctx, uint(2)).Return(int64(3), nil)
	store.On("MarkNotificationRead", ctx, uint(5), uint(2)).Return(nil)
	store.On("MarkAllNotificationsRead", ctx, uint(2)).Return(nil)

	items, err := c.ListNotifications(ctx, 2, true, 10)
	require.NoError(t, err)
	assert.Len(t, items, 1)
	n, err := c.UnreadNotificationCount(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(3), n)
	require.NoError(t, c.MarkNotificationRead(ctx, 5, 2))
	require.NoError(t, c.MarkAllNotificationsRead(ctx, 2))
	store.AssertExpectations(t)
}

func TestNotifySecretShared(t *testing.T) {
	mkCore := func(store *MockStorage) *KeyorixCore {
		return &KeyorixCore{storage: store, now: func() time.Time { return time.Unix(0, 0) }}
	}
	secret := &models.SecretNode{ID: 7, Name: "db", ProjectID: 3}

	t.Run("notifies the recipient with type, message and link", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return n.UserID == 2 && n.Type == NotificationSecretShared
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifySecretShared(ctx, secret, 2, 1, "read")
		store.AssertExpectations(t)
		require.NotNil(t, got)
		assert.Contains(t, got.Message, "read access")
		assert.Contains(t, got.Message, "db")
		assert.Equal(t, "/secrets/7", got.Link)
		require.NotNil(t, got.ProjectID)
		assert.Equal(t, uint(3), *got.ProjectID)
	})

	t.Run("skips a self-share (recipient == sharer)", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		c.notifySecretShared(context.Background(), secret, 1, 1, "read")
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})

	t.Run("skips a zero recipient", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		c.notifySecretShared(context.Background(), secret, 0, 1, "read")
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})
}

func TestNotifySecretOwnershipTransferred(t *testing.T) {
	mkCore := func(store *MockStorage) *KeyorixCore {
		return &KeyorixCore{storage: store, now: func() time.Time { return time.Unix(0, 0) }}
	}
	secret := &models.SecretNode{ID: 7, Name: "db", ProjectID: 3}

	t.Run("notifies the new owner", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return n.UserID == 2 && n.Type == NotificationSecretOwnershipTransferred
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifySecretOwnershipTransferred(ctx, secret, 2, 1)
		store.AssertExpectations(t)
		require.NotNil(t, got)
		assert.Contains(t, got.Message, "owner of secret")
		assert.Equal(t, "/secrets/7", got.Link)
	})

	t.Run("skips a self-transfer (new owner == actor)", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		c.notifySecretOwnershipTransferred(context.Background(), secret, 1, 1)
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})
}

func TestNotifySecretsReassigned(t *testing.T) {
	mkCore := func(store *MockStorage) *KeyorixCore {
		return &KeyorixCore{storage: store, now: func() time.Time { return time.Unix(0, 0) }}
	}

	t.Run("one summary notification with the count", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		ctx := context.Background()
		var got *models.Notification
		store.On("CreateNotification", ctx, mock.MatchedBy(func(n *models.Notification) bool {
			got = n
			return n.UserID == 3
		})).Return(&models.Notification{ID: 1}, nil)

		c.notifySecretsReassigned(ctx, 3, 1, 5, 4)
		store.AssertExpectations(t)
		require.NotNil(t, got)
		assert.Contains(t, got.Message, "4 secret(s)")
		assert.Equal(t, NotificationSecretOwnershipTransferred, got.Type)
	})

	t.Run("skips when nothing was reassigned", func(t *testing.T) {
		store := new(MockStorage)
		c := mkCore(store)
		c.notifySecretsReassigned(context.Background(), 3, 1, 5, 0)
		store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
	})
}
