package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

type fakeSink struct{ events []NotificationEvent }

func (f *fakeSink) Deliver(ev NotificationEvent) { f.events = append(f.events, ev) }

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

	sent, err := c.SendComplianceDigest(context.Background())
	require.NoError(t, err)
	assert.True(t, sent)
	assert.Len(t, broadcast.events, 1, "the compliance digest is deployment-wide and belongs on the broadcast sink")
	assert.Empty(t, recipient.events, "the compliance digest is not addressed to any specific user")
}
