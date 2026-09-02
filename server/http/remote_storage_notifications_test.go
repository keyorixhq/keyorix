// remote_storage_notifications_test.go — end-to-end coverage for #1589:
// RemoteStorage.CreateNotification was an unconditional stub, so every
// notification-worthy core action (access requests, membership activation,
// secret sharing, ...) silently lost its notification under
// storage.type: remote — notifyWithSeverity's best-effort, error-swallowing
// contract (internal/core/notifications.go) meant the triggering action still
// reported success. Mirrors remote_storage_access_request_test.go's harness:
// a real "upstream" exercised through the production NewRouter/handlers
// (including the new /api/v1/system/notifications route,
// server/http/handlers/notification_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote pointed at
// "upstream" over real HTTP via store.RemoteStorage.
package http

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorageCreateNotification_RealServer proves the storage
// primitive itself: a notification created via the DOWNSTREAM's
// RemoteStorage is genuinely persisted on the upstream server, retrievable
// with every field intact.
func TestRemoteStorageCreateNotification_RealServer(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	now := time.Now()

	created, err := downstream.Storage().CreateNotification(ctx, &models.Notification{
		UserID:    55,
		ProjectID: &projectID,
		Type:      "access_request.created",
		Title:     "New access request",
		Message:   "User 42 requested developer access to Payments.",
		Link:      "/projects/1",
		CreatedAt: now,
	})
	require.NoError(t, err, "creating a notification must succeed via storage.type: remote")
	require.NotZero(t, created.ID, "the upstream must assign a real ID")

	// ListNotifications is self-scoped (the server derives the caller from the
	// authenticated token, per remote_notifications.go's own doc) -- it cannot
	// be used here to read back an ARBITRARY userID's notifications through
	// `downstream`'s own (node-authenticated) RemoteStorage client. Read
	// directly off the upstream's own LocalStorage instead, exactly as
	// remote_storage_access_request_test.go's create test verifies "a REAL row
	// in the upstream's own storage, not just 'the call didn't error'".
	fetched, err := upstream.Storage().ListNotifications(ctx, 55, false, 10)
	require.NoError(t, err)
	require.Len(t, fetched, 1)
	assert.Equal(t, "access_request.created", fetched[0].Type)
	assert.Equal(t, "New access request", fetched[0].Title)
	assert.Equal(t, projectID, *fetched[0].ProjectID)
	assert.False(t, fetched[0].IsRead, "a newly-created notification must start unread")
}

// TestRemoteStorageCreateNotification_ClosesTheFailsOpenLoop is the #1589
// finding itself, closed end to end: RequestProjectAccess run against the
// DOWNSTREAM core (storage.type: remote — the exact `keyorix request access`
// liveness chain traced in #1589) must result in a REAL, persisted
// notification for the project's approver on the upstream server. Before
// this fix, RequestProjectAccess still succeeded (notifyWithSeverity
// swallows the CreateNotification error), but this assertion would have
// failed: zero notifications, with no error anywhere to say so.
func TestRemoteStorageCreateNotification_ClosesTheFailsOpenLoop(t *testing.T) {
	upstream, downstream, projectID, _ := newUpstreamDownstreamForAccessRequests(t)
	ctx := context.Background()
	const pw = "Qr7#Kp2$Lm5@Vn9!"

	approver, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "notif-1589-approver", Email: "notif-1589-approver@example.com", Password: pw,
	})
	require.NoError(t, err)
	// project_admin is one of notify's own approverRoleNames
	// (internal/core/notifications.go) — the exact role notifyAccessRequested
	// checks for before notifying a project member of a new request.
	require.NoError(t, upstream.AddProjectMember(ctx, 0, projectID, approver.ID, "project_admin", false))

	requester, err := upstream.CreateUser(ctx, &core.CreateUserRequest{
		Username: "notif-1589-requester", Email: "notif-1589-requester@example.com", Password: pw,
	})
	require.NoError(t, err)

	// The exact live call traced in #1589: RequestProjectAccess against a
	// storage.type: remote-backed core, the same core.KeyorixCore method
	// `keyorix request access` (internal/cli/request/access.go) invokes.
	_, err = downstream.RequestProjectAccess(ctx, projectID, requester.ID, "project_viewer", "on-call rotation")
	require.NoError(t, err, "the request itself must still succeed -- notification delivery is a side effect, not a precondition")

	// The real, falsifiable claim #1589 was about: did the approver actually
	// get notified? Read directly off the upstream's own storage, not through
	// `downstream` -- this is what a genuinely-fixed proxy must have written.
	notifications, err := upstream.Storage().ListNotifications(ctx, approver.ID, false, 10)
	require.NoError(t, err)
	require.Len(t, notifications, 1, "the approver must have received exactly one real notification row on the upstream server")
	assert.Equal(t, core.NotificationAccessRequested, notifications[0].Type)
	assert.Contains(t, notifications[0].Message, "project_viewer")
	assert.WithinDuration(t, time.Now(), notifications[0].CreatedAt, 10*time.Second)
}
