package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCreateNotificationChannel_Validation(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	t.Run("invalid type returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "bad-type", Type: "sms", URL: "https://example.com"}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid notification channel type")
	})

	t.Run("empty name returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "", Type: "webhook", URL: "https://example.com"}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})
}

func TestCreateNotificationChannel_WebhookRequiresURL(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	t.Run("webhook without URL returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-hook", Type: "webhook", URL: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})

	t.Run("email type without email returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-email", Type: "email", Email: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "email is required")
	})

	t.Run("slack without URL returns error", func(t *testing.T) {
		ch := &models.NotificationChannel{Name: "my-slack", Type: "slack", URL: ""}
		_, err := c.CreateNotificationChannel(ctx, ch, "admin")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "URL is required")
	})
}

func TestNotificationChannel_CRUD(t *testing.T) {
	store := new(MockStorage)
	c := NewKeyorixCore(store)
	ctx := context.Background()

	created := &models.NotificationChannel{
		ID:    1,
		Name:  "webhook-siem",
		Type:  "webhook",
		URL:   "https://siem.example.com/hook",
		Events: "anomaly.detected,secret.expiring",
	}

	// Create
	store.On("CreateNotificationChannel", ctx, mock.MatchedBy(func(ch *models.NotificationChannel) bool {
		return ch.Name == "webhook-siem" && ch.Type == "webhook"
	})).Return(nil).Run(func(args mock.Arguments) {
		ch := args.Get(1).(*models.NotificationChannel)
		ch.ID = 1
	})

	result, err := c.CreateNotificationChannel(ctx, &models.NotificationChannel{
		Name:  "webhook-siem",
		Type:  "webhook",
		URL:   "https://siem.example.com/hook",
		Events: "anomaly.detected,secret.expiring",
	}, "admin")
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
	assert.Equal(t, "admin", result.CreatedBy)

	// List
	store.On("ListNotificationChannels", ctx).Return([]*models.NotificationChannel{created}, nil)
	channels, err := c.ListNotificationChannels(ctx)
	require.NoError(t, err)
	require.Len(t, channels, 1)
	assert.Equal(t, "webhook-siem", channels[0].Name)

	// Get
	store.On("GetNotificationChannel", ctx, uint(1)).Return(created, nil)
	got, err := c.GetNotificationChannel(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, "webhook-siem", got.Name)

	// Update
	store.On("GetNotificationChannel", ctx, uint(1)).Return(created, nil).Maybe()
	store.On("UpdateNotificationChannel", ctx, mock.AnythingOfType("*models.NotificationChannel")).Return(nil)
	updated, err := c.UpdateNotificationChannel(ctx, 1, map[string]interface{}{
		"events":  "secret.rotated",
		"enabled": false,
	})
	require.NoError(t, err)
	assert.Equal(t, "secret.rotated", updated.Events)
	assert.False(t, updated.Enabled)

	// Delete
	store.On("DeleteNotificationChannel", ctx, uint(1)).Return(nil)
	require.NoError(t, c.DeleteNotificationChannel(ctx, 1))

	store.AssertExpectations(t)
}
