package core

import (
	"context"
	"testing"

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
