package store

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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

func TestGetNotificationChannelByName_Found(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	orig := &models.NotificationChannel{Name: "find-me", Type: "slack", URL: "https://hooks.slack.com/xyz", Enabled: true}
	require.NoError(t, ls.CreateNotificationChannel(ctx, orig))

	got, err := ls.GetNotificationChannelByName(ctx, "find-me")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "find-me", got.Name)
	assert.Equal(t, "slack", got.Type)
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

// TestGetNotificationChannel_NotFound verifies that the ErrRecordNotFound path
// returns an error containing "not found" (not the generic retrieval error).
func TestGetNotificationChannel_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	_, err := ls.GetNotificationChannel(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestUpdateNotificationChannel_NotFound verifies the RowsAffected==0 path when
// updating a channel that does not exist.
func TestUpdateNotificationChannel_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ghost := &models.NotificationChannel{
		ID:     9999,
		Name:   "ghost",
		Type:   "webhook",
		URL:    "https://ghost.example.com",
		Events: "anomaly.detected",
	}
	err := ls.UpdateNotificationChannel(ctx, ghost)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestDeleteNotificationChannel_NotFound verifies the RowsAffected==0 path when
// deleting a channel that does not exist.
func TestDeleteNotificationChannel_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	err := ls.DeleteNotificationChannel(ctx, 9999)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetNotificationChannelByName_DBError verifies the generic DB error path in
// GetNotificationChannelByName (non-ErrRecordNotFound).
func TestGetNotificationChannelByName_DBError(t *testing.T) {
	ctx := context.Background()

	// Open a DB without the required table to provoke a real DB error.
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — the table doesn't exist, causing a "no such table" error.

	_, err = ls.GetNotificationChannelByName(ctx, "any")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}

// TestGetNotificationChannel_DBError verifies the generic (non-ErrRecordNotFound)
// error branch in GetNotificationChannel.
func TestGetNotificationChannel_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — table missing.

	_, err = ls.GetNotificationChannel(ctx, 1)
	require.Error(t, err)
	// Should NOT be "not found" — the generic retrieval error wraps the real DB err.
	assert.NotContains(t, err.Error(), "not found")
}

// TestUpdateNotificationRetryPolicy_HappyPath verifies that the retry fields
// are updated correctly.
func TestUpdateNotificationRetryPolicy_HappyPath(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	ch := &models.NotificationChannel{Name: "retry-ch", Type: "webhook", URL: "https://example.com/hook", Enabled: true}
	require.NoError(t, ls.CreateNotificationChannel(ctx, ch))

	require.NoError(t, ls.UpdateNotificationRetryPolicy(ctx, ch.ID, 7, 3000))

	got, err := ls.GetNotificationChannel(ctx, ch.ID)
	require.NoError(t, err)
	assert.Equal(t, 7, got.MaxRetries)
	assert.Equal(t, 3000, got.RetryBackoffMs)
}

// TestUpdateNotificationRetryPolicy_NotFound verifies the RowsAffected==0 path.
func TestUpdateNotificationRetryPolicy_NotFound(t *testing.T) {
	ctx := context.Background()
	ls := newNotificationChannelTestStore(t)

	err := ls.UpdateNotificationRetryPolicy(ctx, 9999, 3, 1000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestUpdateNotificationRetryPolicy_DBError verifies the generic DB error path.
func TestUpdateNotificationRetryPolicy_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — table missing.

	err = ls.UpdateNotificationRetryPolicy(ctx, 1, 3, 1000)
	require.Error(t, err)
}

// TestListNotificationChannels_DBError verifies the generic DB error branch in
// ListNotificationChannels (non-nil res.Error when the table is missing).
func TestListNotificationChannels_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — the notification_channels table does not exist.

	_, err = ls.ListNotificationChannels(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}

// TestCreateNotificationChannel_DBError verifies the error branch in
// CreateNotificationChannel when the underlying DB write fails.
func TestCreateNotificationChannel_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — the notification_channels table does not exist.

	ch := &models.NotificationChannel{Name: "err-ch", Type: "webhook", URL: "https://example.com"}
	err = ls.CreateNotificationChannel(ctx, ch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}

// TestUpdateNotificationChannel_DBError verifies the res.Error != nil branch in
// UpdateNotificationChannel (distinct from the RowsAffected==0 not-found branch).
func TestUpdateNotificationChannel_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — the notification_channels table does not exist.

	ch := &models.NotificationChannel{
		ID:   1,
		Name: "err-ch",
		Type: "webhook",
		URL:  "https://example.com",
	}
	err = ls.UpdateNotificationChannel(ctx, ch)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}

// TestDeleteNotificationChannel_DBError verifies the res.Error != nil branch in
// DeleteNotificationChannel (distinct from the RowsAffected==0 not-found branch).
func TestDeleteNotificationChannel_DBError(t *testing.T) {
	ctx := context.Background()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	ls := NewLocalStorage(db)
	// No AutoMigrate — the notification_channels table does not exist.

	err = ls.DeleteNotificationChannel(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no such table")
}
