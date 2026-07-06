package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_Notifications_RealServerRoundTrip proves the fix for the
// RemoteStorage stub-coverage audit (round 116): ListNotifications and
// CountUnreadNotifications were unconditional storage.ErrUnsupportedByBackend
// stubs even though a real, self-scoped GET /notifications route exists
// (ADR-024). MarkNotificationRead/MarkAllNotificationsRead were already wired
// and are re-verified here alongside the two fixes for good measure.
//
// Drives every method through a REAL running server (NewRouter) via a REAL
// RemoteStorage client over real HTTP, per this package's established pattern
// (see TestRemoteStorage_GetUserByEmail_RealServerRoundTrip).
func TestRemoteStorage_Notifications_RealServerRoundTrip(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	upstreamToken := createTestToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	admin, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	// Seed three notifications directly against the upstream's own storage —
	// exactly what internal/core/notifications.go's notify() does server-side —
	// two unread, one already read, so List/Count have real, distinct data to
	// prove against rather than an empty inbox.
	var seeded []*models.Notification
	for _, n := range []*models.Notification{
		{UserID: admin.ID, Type: "secret.shared", Title: "Shared", Message: "m1"},
		{UserID: admin.ID, Type: "access_request.approved", Title: "Approved", Message: "m2"},
		{UserID: admin.ID, Type: "membership.activated", Title: "Activated", Message: "m3", IsRead: true},
	} {
		created, err := upstreamCore.Storage().CreateNotification(ctx, n)
		require.NoError(t, err)
		seeded = append(seeded, created)
	}

	newClient := func(token string) *store.RemoteStorage {
		rs, err := store.NewRemoteStorage(&remote.Config{
			BaseURL:        upstreamSrv.URL,
			APIKey:         token,
			TimeoutSeconds: 5,
			RetryAttempts:  0,
			TLSVerify:      true,
		})
		require.NoError(t, err)
		return rs
	}

	rs := newClient(upstreamToken)

	// --- ListNotifications: must reach the real route and decode every field
	// correctly, not just the case-insensitively-lucky ones (#496-class bug) ---
	all, err := rs.ListNotifications(ctx, admin.ID, false, 0)
	require.NoError(t, err, "ListNotifications must reach the real GET /notifications route (round-116 fix)")
	require.Len(t, all, 3, "all three seeded notifications")

	// Newest-first ordering, and the already-read one's IsRead must round-trip
	// as true — this is exactly the field encoding/json's case-insensitive
	// fallback would silently zero without the wire DTO (is_read != IsRead).
	var readCount, unreadCount int
	var sawReadTitle string
	for _, n := range all {
		if n.IsRead {
			readCount++
			sawReadTitle = n.Title
		} else {
			unreadCount++
		}
		assert.NotZero(t, n.ID, "id must round-trip")
		assert.NotEmpty(t, n.Type, "type must round-trip")
		assert.NotEmpty(t, n.Title, "title must round-trip")
		assert.NotEmpty(t, n.Message, "message must round-trip")
		assert.False(t, n.CreatedAt.IsZero(), "created_at must round-trip, not silently zero")
	}
	assert.Equal(t, 1, readCount)
	assert.Equal(t, 2, unreadCount)
	assert.Equal(t, "Activated", sawReadTitle)

	// unread=true must filter server-side.
	unreadOnly, err := rs.ListNotifications(ctx, admin.ID, true, 0)
	require.NoError(t, err)
	assert.Len(t, unreadOnly, 2)

	// limit must be honored.
	limited, err := rs.ListNotifications(ctx, admin.ID, false, 1)
	require.NoError(t, err)
	assert.Len(t, limited, 1)

	// --- CountUnreadNotifications: must reach the real route (round-116 fix) ---
	count, err := rs.CountUnreadNotifications(ctx, admin.ID)
	require.NoError(t, err, "CountUnreadNotifications must reach the real GET /notifications route (round-116 fix)")
	assert.Equal(t, int64(2), count)

	// --- MarkNotificationRead: mark one of the two unread ones ---
	var unreadID uint
	for _, n := range seeded {
		if !n.IsRead {
			unreadID = n.ID
			break
		}
	}
	require.NotZero(t, unreadID)
	require.NoError(t, rs.MarkNotificationRead(ctx, unreadID, admin.ID))

	count, err = rs.CountUnreadNotifications(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "marking one read must drop the unread count by one")

	// --- MarkAllNotificationsRead: zero unread afterward ---
	require.NoError(t, rs.MarkAllNotificationsRead(ctx, admin.ID))
	count, err = rs.CountUnreadNotifications(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// TestRemoteStorage_Notifications_ScopingPreserved proves the passthrough
// preserves ADR-024's self-scoping: a RemoteStorage client only ever sees/
// mutates the notifications belonging to whichever identity its own token
// authenticates as. The storage.Storage interface's userID parameter is
// deliberately NOT sent on the wire (see fetchNotifications/
// MarkNotificationRead's doc comments) — the server derives the caller from the
// authenticated session, so passing a different user's ID can never widen
// access. This is enforced entirely at the handler layer (middleware.
// GetUserFromContext + LocalStorage's `WHERE user_id = ?` scoping), not by any
// check inside RemoteStorage itself — this test proves that server-side
// enforcement holds end-to-end through the real remote client, not that
// RemoteStorage adds its own redundant check.
func TestRemoteStorage_Notifications_ScopingPreserved(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstreamCore := newTestCore(t)
	adminToken := createTestToken(t, upstreamCore)
	limitedToken := createLimitedToken(t, upstreamCore)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	defer upstreamSrv.Close()

	ctx := context.Background()

	admin, err := upstreamCore.Storage().GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	limited, err := upstreamCore.Storage().GetUserByEmail(ctx, "limited@example.com")
	require.NoError(t, err)

	adminNote, err := upstreamCore.Storage().CreateNotification(ctx, &models.Notification{
		UserID: admin.ID, Type: "secret.shared", Title: "Admin's", Message: "admin-only",
	})
	require.NoError(t, err)
	limitedNote, err := upstreamCore.Storage().CreateNotification(ctx, &models.Notification{
		UserID: limited.ID, Type: "secret.shared", Title: "Limited's", Message: "limited-only",
	})
	require.NoError(t, err)

	newClient := func(token string) *store.RemoteStorage {
		rs, err := store.NewRemoteStorage(&remote.Config{
			BaseURL:        upstreamSrv.URL,
			APIKey:         token,
			TimeoutSeconds: 5,
			RetryAttempts:  0,
			TLSVerify:      true,
		})
		require.NoError(t, err)
		return rs
	}

	adminRS := newClient(adminToken)
	limitedRS := newClient(limitedToken)

	// --- List: each client only ever sees its own identity's notification,
	// even when the (unused-on-the-wire) userID argument names the OTHER user ---
	adminList, err := adminRS.ListNotifications(ctx, limited.ID, false, 0)
	require.NoError(t, err)
	require.Len(t, adminList, 1)
	assert.Equal(t, "Admin's", adminList[0].Title,
		"admin's token must return only admin's own notification, regardless of the userID argument passed")

	limitedList, err := limitedRS.ListNotifications(ctx, admin.ID, false, 0)
	require.NoError(t, err)
	require.Len(t, limitedList, 1)
	assert.Equal(t, "Limited's", limitedList[0].Title,
		"limited's token must return only limited's own notification, regardless of the userID argument passed")

	// --- Count: same identity-scoping, same argument-is-ignored property ---
	adminCount, err := adminRS.CountUnreadNotifications(ctx, limited.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), adminCount)

	limitedCount, err := limitedRS.CountUnreadNotifications(ctx, admin.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), limitedCount)

	// --- MarkNotificationRead: the limited user CANNOT mark the admin's
	// notification read by ID, even though it authenticates fine and the ID is
	// a real, existing row — it is simply not scoped to this caller ---
	err = limitedRS.MarkNotificationRead(ctx, adminNote.ID, admin.ID)
	require.Error(t, err, "a caller must not be able to mark another user's notification read by ID")

	// The admin's notification must still be unread — the cross-user attempt
	// above must not have mutated it.
	stillThere, err := upstreamCore.Storage().ListNotifications(ctx, admin.ID, true, 0)
	require.NoError(t, err)
	require.Len(t, stillThere, 1)
	assert.Equal(t, adminNote.ID, stillThere[0].ID)

	// Conversely, the admin cannot mark the limited user's notification read.
	err = adminRS.MarkNotificationRead(ctx, limitedNote.ID, limited.ID)
	require.Error(t, err, "a caller must not be able to mark another user's notification read by ID")

	stillThereLimited, err := upstreamCore.Storage().ListNotifications(ctx, limited.ID, true, 0)
	require.NoError(t, err)
	require.Len(t, stillThereLimited, 1)
	assert.Equal(t, limitedNote.ID, stillThereLimited[0].ID)

	// --- MarkAllNotificationsRead: scoped the same way — marking "all read"
	// as the limited user must not touch the admin's notification ---
	require.NoError(t, limitedRS.MarkAllNotificationsRead(ctx, admin.ID))
	adminStillUnread, err := upstreamCore.Storage().ListNotifications(ctx, admin.ID, true, 0)
	require.NoError(t, err)
	assert.Len(t, adminStillUnread, 1, "limited user's mark-all-read must not affect admin's notifications")
}
