package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// newRotationReminderCore sets up a real-SQLite core with one project, a
// project_admin member (user 5), and a secret overdue under an active rotation
// policy, for exercising SendRotationReminders end to end.
func newRotationReminderCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.RotationPolicy{}, &models.Notification{},
	))

	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 6, Username: "viewer", Email: "v@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "project_viewer"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error) // admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 6, RoleID: 2, ProjectID: 1}).Error) // viewer (no reminder)
	// A secret created 100 days ago, never rotated → overdue under a 30-day policy.
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 10, Name: "db-password", ProjectID: 1, EnvironmentID: 2, Type: "password",
		CreatedAt: now.AddDate(0, 0, -100),
	}).Error)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		Name: "30-day", Scope: "project", ProjectID: &pid,
		IntervalDays: 30, AlertDaysBefore: 7, IsActive: true, CreatedBy: "ada",
	}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db, now
}

func TestSendRotationReminders(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newRotationReminderCore(t)

	// First run: the project_admin (user 5) is notified; the viewer (user 6) is not.
	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "only the project admin is notified")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationRotationDue).Find(&notes).Error)
	require.Len(t, notes, 1)
	assert.Equal(t, uint(5), notes[0].UserID)
	require.NotNil(t, notes[0].ProjectID)
	assert.Equal(t, uint(1), *notes[0].ProjectID)
	assert.Contains(t, notes[0].Message, "overdue")
	assert.Contains(t, notes[0].Message, "payments")

	// Second run while the reminder is still UNREAD: deduped — no new notification.
	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "a standing unread reminder is not duplicated")
	var n int64
	require.NoError(t, db.Model(&models.Notification{}).Where("type = ?", NotificationRotationDue).Count(&n).Error)
	assert.Equal(t, int64(1), n)

	// Once read, a still-overdue secret nudges the admin again on the next run.
	require.NoError(t, db.Model(&models.Notification{}).Where("id = ?", notes[0].ID).Update("is_read", true).Error)
	sent, err = c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "after reading, a still-overdue secret re-notifies")
}

// TestHasUnreadRotationReminder_NotBuriedByNotificationVolume is a regression test
// for #399: the dedup check must find a genuine standing rotation reminder even
// when it's buried under more than 100 newer, unrelated unread notifications — it
// must not depend on the reminder happening to fall inside a "newest N of any
// type" window.
func TestHasUnreadRotationReminder_NotBuriedByNotificationVolume(t *testing.T) {
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)

	// Seed the genuine rotation reminder first (oldest), then bury it under 150
	// newer, unrelated unread notifications for the same user.
	pid := uint(1)
	require.NoError(t, db.Create(&models.Notification{
		UserID: 5, ProjectID: &pid, Type: NotificationRotationDue,
		Title: "Secrets due for rotation", Message: "old standing reminder",
		IsRead: false, CreatedAt: now.Add(-24 * time.Hour),
	}).Error)
	for i := 0; i < 150; i++ {
		require.NoError(t, db.Create(&models.Notification{
			UserID: 5, ProjectID: &pid, Type: NotificationAccessRequested,
			Title: "Unrelated", Message: "noise",
			IsRead: false, CreatedAt: now.Add(time.Duration(i) * time.Minute),
		}).Error)
	}

	assert.True(t, c.hasUnreadRotationReminder(ctx, 5, 1),
		"the standing reminder must be found even though 150 newer unread notifications of another type exist")

	// The straightforward case (no volume issue, no reminder) still works.
	assert.False(t, c.hasUnreadRotationReminder(ctx, 6, 1),
		"a user with no rotation reminder at all must not be reported as having one")

	// SendRotationReminders itself must not duplicate the reminder despite the noise.
	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "the buried-but-genuine reminder still dedupes the run")
	var n int64
	require.NoError(t, db.Model(&models.Notification{}).
		Where("type = ? AND user_id = ?", NotificationRotationDue, 5).Count(&n).Error)
	assert.Equal(t, int64(1), n, "no duplicate rotation reminder was created")
}

func TestSendRotationReminders_NothingDue(t *testing.T) {
	ctx := context.Background()
	c, db, now := newRotationReminderCore(t)
	// Rotate the secret now → no longer overdue/approaching.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).Update("last_rotated_at", now).Error)

	sent, err := c.SendRotationReminders(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, sent)
}

func TestRotationReminderMessage(t *testing.T) {
	assert.Contains(t, rotationReminderMessage("p", 3, 2), "3 secret(s) in p are overdue")
	assert.Contains(t, rotationReminderMessage("p", 3, 2), "2 more are approaching")
	assert.Equal(t, "1 secret(s) in p are overdue for rotation.", rotationReminderMessage("p", 1, 0))
	assert.Contains(t, rotationReminderMessage("p", 0, 4), "approaching their rotation deadline")
}
