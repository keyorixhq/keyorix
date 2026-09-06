// notification_channel_audit_test.go — regression coverage for the
// notification-channel audit-trail gap: CreateNotificationChannel,
// UpdateNotificationChannel, and DeleteNotificationChannel used to call no
// writeAuditEvent/writeConfigChangeAuditEvent at all, unlike the sibling
// retry-policy path (SetNotificationRetryPolicy, notification_retry.go),
// which already audited as notification_channel.retry_policy_updated. An
// admin repointing a webhook URL to an attacker-controlled endpoint, or
// deleting the channel outright, left zero permanent record -- only a
// self-overwriting UpdatedAt on the row (no UpdatedBy field even exists on
// the model). Each test here performs the mutation and asserts the exact
// audit event (type/actor/diff) that must now exist.
//
// Verified RED before the fix: reverting the writeConfigChangeAuditEvent call
// in any of the three functions makes the corresponding test below fail with
// "0 calls" to LogAuditEvent (confirmed manually during development of this
// fix -- see config_change_audit_guard_test.go for the permanent structural
// guard against a silent regression).
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateNotificationChannel_AuditsCreation(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	store.On("CreateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).
		Return(nil).
		Run(func(args mock.Arguments) {
			args.Get(1).(*models.NotificationChannel).ID = 11
		})
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	const actorID = uint(9001)
	ch := &models.NotificationChannel{
		Name: "siem-webhook", Type: "webhook", URL: "https://siem.example.com/hook",
	}
	created, err := c.CreateNotificationChannel(ctx, ch, "admin", actorID)
	require.NoError(t, err)
	require.NotNil(t, created)

	require.NotNil(t, captured, "creating a notification channel must write an audit event")
	assert.Equal(t, EventNotificationChannelCreated, captured.EventType)
	require.NotNil(t, captured.UserID, "the acting admin must be attributed by numeric ID")
	assert.Equal(t, actorID, *captured.UserID)
	assert.Contains(t, captured.Diff, "siem-webhook", "the diff must carry the created channel's name")
	assert.Contains(t, captured.Diff, "https://siem.example.com/hook", "the diff must carry the channel URL -- the security-relevant field an admin could redirect")
	store.AssertExpectations(t)
}

func TestUpdateNotificationChannel_AuditsURLChange(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID: 22, Name: "ops-webhook", Type: "webhook",
		URL: "https://legit.example.com/hook", Enabled: true,
	}
	store.On("GetNotificationChannel", ctx, uint(22)).Return(existing, nil)
	store.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	const actorID = uint(9002)
	// The threat this closes: an admin silently repoints where alerts are
	// delivered, e.g. to an attacker-controlled endpoint.
	updated, err := c.UpdateNotificationChannel(ctx, 22, map[string]any{
		"url": "https://attacker.example.net/collect",
	}, actorID)
	require.NoError(t, err)
	require.NotNil(t, updated)

	require.NotNil(t, captured, "updating a notification channel must write an audit event")
	assert.Equal(t, EventNotificationChannelUpdated, captured.EventType)
	require.NotNil(t, captured.UserID)
	assert.Equal(t, actorID, *captured.UserID)
	assert.Contains(t, captured.Diff, "https://legit.example.com/hook", "the diff must carry the PRIOR (before) URL")
	assert.Contains(t, captured.Diff, "https://attacker.example.net/collect", "the diff must carry the NEW (after) URL")
	store.AssertExpectations(t)
}

func TestUpdateNotificationChannel_AuditsEnabledFlagChange(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	c.webhookURLValidator = noopWebhookURLValidator
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID: 23, Name: "siem-webhook", Type: "webhook",
		URL: "https://siem.example.com/hook", Enabled: true,
	}
	store.On("GetNotificationChannel", ctx, uint(23)).Return(existing, nil)
	store.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	// The threat this closes: an admin silently disables the channel (the
	// alerts stop arriving) without ever changing the URL.
	_, err := c.UpdateNotificationChannel(ctx, 23, map[string]any{"enabled": false}, 9003)
	require.NoError(t, err)

	require.NotNil(t, captured)
	assert.Contains(t, captured.Diff, `"enabled":true`, "the diff must carry the PRIOR enabled state")
	assert.Contains(t, captured.Diff, `"enabled":false`, "the diff must carry the NEW enabled state")
}

func TestDeleteNotificationChannel_AuditsDeletion(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	existing := &models.NotificationChannel{
		ID: 33, Name: "siem-webhook", Type: "webhook", URL: "https://siem.example.com/hook",
	}
	store.On("GetNotificationChannel", ctx, uint(33)).Return(existing, nil)
	store.On("DeleteNotificationChannel", ctx, uint(33)).Return(nil)
	var captured *models.AuditEvent
	store.On("LogAuditEvent", ctx, mock.AnythingOfType("*models.AuditEvent")).
		Run(func(args mock.Arguments) { captured = args.Get(1).(*models.AuditEvent) }).
		Return(nil)

	const actorID = uint(9004)
	require.NoError(t, c.DeleteNotificationChannel(ctx, 33, actorID))

	require.NotNil(t, captured, "deleting a notification channel must write an audit event")
	assert.Equal(t, EventNotificationChannelDeleted, captured.EventType)
	require.NotNil(t, captured.UserID)
	assert.Equal(t, actorID, *captured.UserID)
	assert.Contains(t, captured.Diff, "siem-webhook", "the diff must record what was deleted")
	store.AssertExpectations(t)
}

// TestDeleteNotificationChannel_NotFound_NoAuditEvent confirms a delete
// attempt on a nonexistent channel writes NO audit event (nothing was
// actually deleted) -- the Get-before-Delete added by this fix must not
// silently swallow the not-found error either.
func TestDeleteNotificationChannel_NotFound_NoAuditEvent(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	store.On("GetNotificationChannel", ctx, uint(404)).Return(nil, errors.New("not found"))

	err := c.DeleteNotificationChannel(ctx, 404, 1)
	require.Error(t, err)
	store.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "DeleteNotificationChannel", mock.Anything, mock.Anything)
}
