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

// newExpiryReminderCore sets up a real-SQLite core with one project, a project_admin
// member (user 5) and a viewer (user 6), and secrets in various expiry states.
func newExpiryReminderCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.Notification{},
	))

	now := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)
	at := func(days int) *time.Time { t := now.AddDate(0, 0, days); return &t }
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 6, Username: "viewer", Email: "v@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "project_viewer"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error) // admin
	require.NoError(t, db.Create(&models.UserRole{UserID: 6, RoleID: 2, ProjectID: 1}).Error) // viewer

	base := models.SecretNode{ProjectID: 1, EnvironmentID: 2, Type: "password", CreatedAt: now}
	expired := base
	expired.ID, expired.Name, expired.Expiration = 10, "expired-key", at(-1) // already expired
	soon := base
	soon.ID, soon.Name, soon.Expiration = 11, "soon-key", at(7) // within the 14-day lead
	far := base
	far.ID, far.Name, far.Expiration = 12, "far-key", at(60) // outside the lead window
	noExp := base
	noExp.ID, noExp.Name = 13, "no-expiry" // no expiration at all
	for _, s := range []models.SecretNode{expired, soon, far, noExp} {
		require.NoError(t, db.Create(&s).Error)
	}

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db, now
}

func TestSendExpiryReminders(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newExpiryReminderCore(t)

	// First run: the project_admin (user 5) is notified for the expired + soon secrets;
	// the viewer (user 6) is not; the far-future and no-expiry secrets don't count.
	sent, err := c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "only the project admin is notified")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationExpiryReminder).Find(&notes).Error)
	require.Len(t, notes, 1)
	assert.Equal(t, uint(5), notes[0].UserID)
	require.NotNil(t, notes[0].ProjectID)
	assert.Equal(t, uint(1), *notes[0].ProjectID)
	assert.Contains(t, notes[0].Message, "expired")
	assert.Contains(t, notes[0].Message, "expiring soon")
	assert.Contains(t, notes[0].Message, "payments")

	// Second run while unread: deduped.
	sent, err = c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "a standing unread reminder is not duplicated")

	// Once read, still-expiring secrets nudge again.
	require.NoError(t, db.Model(&models.Notification{}).Where("id = ?", notes[0].ID).Update("is_read", true).Error)
	sent, err = c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "after reading, still-expiring secrets re-notify")
}

func TestSendExpiryReminders_NothingDue(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newExpiryReminderCore(t)
	// Remove the expired + soon secrets; only far-future and no-expiry remain.
	require.NoError(t, db.Where("id IN ?", []uint{10, 11}).Delete(&models.SecretNode{}).Error)

	sent, err := c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 0, sent)
}

func TestExpiryReminderMessage(t *testing.T) {
	assert.Contains(t, expiryReminderMessage("p", 3, 2), "3 secret(s) in p have expired")
	assert.Contains(t, expiryReminderMessage("p", 3, 2), "2 more are expiring soon")
	assert.Equal(t, "1 secret(s) in p have expired.", expiryReminderMessage("p", 1, 0))
	assert.Contains(t, expiryReminderMessage("p", 0, 4), "expiring soon")
}
