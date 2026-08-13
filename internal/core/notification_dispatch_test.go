package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeSink is a NotificationSink test double. refuse, when true, simulates a sink
// that cannot accept the event at all (e.g. the email channel with no recipient and
// no configured broadcast destination, #221): Deliver still records nothing was
// attempted, and returns false so callers can assert on the accurate signal.
type fakeSink struct {
	events []NotificationEvent
	refuse bool
}

func (f *fakeSink) Deliver(ev NotificationEvent) bool {
	if f.refuse {
		return false
	}
	f.events = append(f.events, ev)
	return true
}

func TestNotify_DispatchesToSinkWithResolvedEmail(t *testing.T) {
	store := new(MockStorage)
	store.On("CreateNotification", mock.Anything, mock.Anything).Return(&models.Notification{ID: 1}, nil)
	store.On("GetUser", mock.Anything, uint(7)).Return(&models.User{ID: 7, Email: "ada@x.io"}, nil)

	c := NewKeyorixCore(store)
	sink := &fakeSink{}
	c.SetRecipientNotificationSink(sink)

	pid := uint(3)
	c.notify(context.Background(), 7, NotificationAccessApproved, "Approved", "Your request was approved", &pid, "/projects/3")

	require.Len(t, sink.events, 1)
	ev := sink.events[0]
	assert.Equal(t, uint(7), ev.UserID)
	assert.Equal(t, "ada@x.io", ev.Email, "the recipient's email is resolved for the channel")
	assert.Equal(t, NotificationAccessApproved, ev.Type)
	require.NotNil(t, ev.ProjectID)
	assert.Equal(t, uint(3), *ev.ProjectID)
}

func TestNotify_NoSink_SkipsDispatchAndEmailLookup(t *testing.T) {
	store := new(MockStorage)
	store.On("CreateNotification", mock.Anything, mock.Anything).Return(&models.Notification{ID: 1}, nil)
	// No sink wired → GetUser must never be called (no needless query per notification).
	c := NewKeyorixCore(store)
	c.notify(context.Background(), 7, "x", "t", "m", nil, "")
	store.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
}

func TestNotify_ZeroUser_DoesNothing(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.SetRecipientNotificationSink(&fakeSink{})
	c.notify(context.Background(), 0, "x", "t", "m", nil, "")
	store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}

// #391: a per-user/per-project notification must NEVER reach the deployment-wide
// broadcast sink (the one Slack/Teams/webhook are wired into) — only the
// recipient-addressable sink (email). Before the fix, notify()/dispatchNotification
// handed every event straight to the single deployment-wide notificationSink,
// broadcasting e.g. "secret shared with you" to an entire Slack channel regardless
// of project membership or secret access.
func TestNotify_NeverReachesBroadcastSink(t *testing.T) {
	store := new(MockStorage)
	store.On("CreateNotification", mock.Anything, mock.Anything).Return(&models.Notification{ID: 1}, nil)
	store.On("GetUser", mock.Anything, uint(7)).Return(&models.User{ID: 7, Email: "ada@x.io"}, nil)

	c := NewKeyorixCore(store)
	broadcast := &fakeSink{} // stands in for the Slack/Teams/webhook multi-sink
	recipient := &fakeSink{} // stands in for the email-only sink
	c.SetNotificationSink(broadcast)
	c.SetRecipientNotificationSink(recipient)

	pid := uint(3)
	c.notify(context.Background(), 7, NotificationSecretShared, "Secret shared with you",
		`You were granted read access to secret "prod-db-password".`, &pid, "/secrets/1")

	assert.Empty(t, broadcast.events, "a per-user event must never reach the deployment-wide broadcast sink")
	require.Len(t, recipient.events, 1, "it must still reach the recipient-addressable (email) sink")
	assert.Equal(t, NotificationSecretShared, recipient.events[0].Type)
}

// TestUpgradeReminder_RedispatchesOnEscalation is a regression test for #482: an
// escalation must re-fire the out-of-band delivery channel, not just update the DB
// row. Before the fix, upgradeReminder only called storage.UpdateNotification —
// dispatchNotification (the only path that reaches recipientNotificationSink.Deliver)
// was never invoked on the escalation path, so a Warning reminder silently becoming
// Critical while unread updated Title/Message/Severity in the DB but never re-sent the
// email/webhook that would actually alert the user to the more severe state.
func TestUpgradeReminder_RedispatchesOnEscalation(t *testing.T) {
	store := new(MockStorage)
	store.On("UpdateNotification", mock.Anything, mock.Anything).Return(nil)
	store.On("GetUser", mock.Anything, uint(5)).Return(&models.User{ID: 5, Email: "admin@x.io"}, nil)

	c := NewKeyorixCore(store)
	sink := &fakeSink{}
	c.SetRecipientNotificationSink(sink)

	pid := uint(1)
	existing := &models.Notification{
		ID: 1, UserID: 5, ProjectID: &pid, Type: NotificationRotationDue,
		Title: "Secrets due for rotation", Message: "1 secret(s) approaching",
		Severity: models.NotificationSeverityWarning, Link: "/rotation-policies",
	}

	ok := c.upgradeReminder(context.Background(), existing, "Secrets due for rotation",
		"1 secret(s) overdue for rotation.", models.NotificationSeverityCritical)
	require.True(t, ok)

	require.Len(t, sink.events, 1, "the escalation must re-fire delivery, not just update the DB row")
	ev := sink.events[0]
	assert.Equal(t, uint(5), ev.UserID)
	assert.Equal(t, "admin@x.io", ev.Email)
	assert.Equal(t, NotificationRotationDue, ev.Type)
	assert.Equal(t, "1 secret(s) overdue for rotation.", ev.Message, "the redispatched event carries the escalated message, not the stale one")
	assert.Equal(t, "/rotation-policies", ev.Link)
	require.NotNil(t, ev.ProjectID)
	assert.Equal(t, uint(1), *ev.ProjectID)

	// The in-memory row itself was upgraded in place.
	assert.Equal(t, models.NotificationSeverityCritical, existing.Severity)
}

// TestUpgradeReminder_UpdateFailure_SkipsDispatch ensures a failed DB update does not
// still fire an out-of-band delivery for a row that was never actually persisted.
func TestUpgradeReminder_UpdateFailure_SkipsDispatch(t *testing.T) {
	store := new(MockStorage)
	store.On("UpdateNotification", mock.Anything, mock.Anything).Return(assert.AnError)

	c := NewKeyorixCore(store)
	sink := &fakeSink{}
	c.SetRecipientNotificationSink(sink)

	existing := &models.Notification{ID: 1, UserID: 5, Type: NotificationRotationDue}
	ok := c.upgradeReminder(context.Background(), existing, "t", "m", models.NotificationSeverityCritical)

	assert.False(t, ok)
	assert.Empty(t, sink.events, "a failed persist must not still fire delivery")
	store.AssertNotCalled(t, "GetUser", mock.Anything, mock.Anything)
}

// SendComplianceDigest and notifyRotationFailures are the deliberately-deployment-
// wide, aggregate broadcasts (#391) — they must keep reaching the broadcast sink
// (Slack/Teams/webhook), never the per-user recipient sink (which they don't
// address to any specific user).
func TestSendComplianceDigest_UsesBroadcastSinkNotRecipientSink(t *testing.T) {
	c, _, _ := newEvidenceExportCore(t) // real store, empty deployment
	broadcast := &fakeSink{}
	recipient := &fakeSink{}
	c.SetNotificationSink(broadcast)
	c.SetRecipientNotificationSink(recipient)

	sent, err := c.SendComplianceDigest(context.Background(), 0)
	require.NoError(t, err)
	assert.True(t, sent)
	assert.Len(t, broadcast.events, 1, "the compliance digest is deployment-wide and belongs on the broadcast sink")
	assert.Empty(t, recipient.events, "the compliance digest is not addressed to any specific user")
}
