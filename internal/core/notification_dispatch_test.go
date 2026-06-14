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
	c.SetNotificationSink(sink)

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
	c.SetNotificationSink(&fakeSink{})
	c.notify(context.Background(), 0, "x", "t", "m", nil, "")
	store.AssertNotCalled(t, "CreateNotification", mock.Anything, mock.Anything)
}
