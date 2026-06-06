package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newNotificationStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Notification{}))
	return NewLocalStorage(db)
}

func TestNotifications_CRUD(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationStore(t)

	// User 2: two unread + one already read. User 3: one unread.
	for _, n := range []*models.Notification{
		{UserID: 2, Type: "a", Title: "A", Message: "m1"},
		{UserID: 2, Type: "b", Title: "B", Message: "m2"},
		{UserID: 2, Type: "c", Title: "C", Message: "m3", IsRead: true},
		{UserID: 3, Type: "d", Title: "D", Message: "m4"},
	} {
		_, err := ls.CreateNotification(ctx, n)
		require.NoError(t, err)
	}

	all, err := ls.ListNotifications(ctx, 2, false, 0)
	require.NoError(t, err)
	assert.Len(t, all, 3, "all of user 2's notifications")

	unread, err := ls.ListNotifications(ctx, 2, true, 0)
	require.NoError(t, err)
	assert.Len(t, unread, 2, "only unread")

	count, err := ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Mark one (known-unread) read; the unread count drops.
	require.NoError(t, ls.MarkNotificationRead(ctx, unread[0].ID, 2))
	count, err = ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	// Ownership: user 3 can't mark user 2's notification.
	require.Error(t, ls.MarkNotificationRead(ctx, unread[1].ID, 3))

	// Mark all read for user 2 → zero unread; user 3 untouched.
	require.NoError(t, ls.MarkAllNotificationsRead(ctx, 2))
	count, err = ls.CountUnreadNotifications(ctx, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
	other, err := ls.CountUnreadNotifications(ctx, 3)
	require.NoError(t, err)
	assert.Equal(t, int64(1), other)
}
