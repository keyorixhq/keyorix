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

func newNotificationChannelTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.NotificationChannel{}))
	return NewLocalStorage(db)
}

func TestCreateAndListNotificationChannels(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ch1 := &models.NotificationChannel{Name: "slack-ops", Type: "slack", URL: "https://hooks.slack.com/abc", Enabled: true, Events: "anomaly.detected"}
	ch2 := &models.NotificationChannel{Name: "webhook-siem", Type: "webhook", URL: "https://siem.example.com/hook", Enabled: true, Events: ""}

	require.NoError(t, ls.CreateNotificationChannel(ctx, ch1))
	require.NoError(t, ls.CreateNotificationChannel(ctx, ch2))
	assert.NotZero(t, ch1.ID)
	assert.NotZero(t, ch2.ID)

	channels, err := ls.ListNotificationChannels(ctx)
	require.NoError(t, err)
	require.Len(t, channels, 2)
	assert.Equal(t, "slack-ops", channels[0].Name)
	assert.Equal(t, "webhook-siem", channels[1].Name)
}

func TestGetNotificationChannelByName_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ch, err := ls.GetNotificationChannelByName(ctx, "does-not-exist")
	require.NoError(t, err)
	assert.Nil(t, ch, "GetNotificationChannelByName should return nil, nil for a missing channel")
}

func TestUpdateNotificationChannel(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ch := &models.NotificationChannel{Name: "teams-alerts", Type: "teams", URL: "https://outlook.office.com/webhook/abc", Enabled: true}
	require.NoError(t, ls.CreateNotificationChannel(ctx, ch))

	ch.URL = "https://outlook.office.com/webhook/xyz"
	ch.Enabled = false
	ch.Events = "secret.expiring"
	require.NoError(t, ls.UpdateNotificationChannel(ctx, ch))

	got, err := ls.GetNotificationChannel(ctx, ch.ID)
	require.NoError(t, err)
	assert.Equal(t, "https://outlook.office.com/webhook/xyz", got.URL)
	assert.False(t, got.Enabled)
	assert.Equal(t, "secret.expiring", got.Events)
}

func TestDeleteNotificationChannel(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ch := &models.NotificationChannel{Name: "email-ops", Type: "email", Email: "ops@example.com", Enabled: true}
	require.NoError(t, ls.CreateNotificationChannel(ctx, ch))
	require.NotZero(t, ch.ID)

	require.NoError(t, ls.DeleteNotificationChannel(ctx, ch.ID))

	// Hard delete: row should be gone.
	channels, err := ls.ListNotificationChannels(ctx)
	require.NoError(t, err)
	assert.Empty(t, channels)
}
