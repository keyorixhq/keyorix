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

// TestSendExpiryReminders_EscalatesOnMoreSevereState is a regression test for
// #250: an unread standing expiry reminder recorded at Warning (expiring soon)
// must be escalated in place — not silently suppressed — once the secret has
// genuinely expired (Critical) while that reminder is still unread.
func TestSendExpiryReminders_EscalatesOnMoreSevereState(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newExpiryReminderCore(t)
	// Drop the already-expired secret; only the "soon" secret remains due →
	// first run is Warning-only.
	require.NoError(t, db.Where("id = ?", 10).Delete(&models.SecretNode{}).Error)

	sent, err := c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	require.Equal(t, 1, sent)

	var note models.Notification
	require.NoError(t, db.Where("type = ?", NotificationExpiryReminder).First(&note).Error)
	assert.Equal(t, models.NotificationSeverityWarning, note.Severity)
	firstID := note.ID

	// Now that secret has also expired (soon-key's expiry moved into the past)
	// while the Warning reminder is still unread: escalate to Critical.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 11).
		Update("expiration", note.CreatedAt.AddDate(0, 0, -1)).Error)

	sent, err = c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "the escalation to expired must reach the admin")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationExpiryReminder).Find(&notes).Error)
	require.Len(t, notes, 1, "the standing reminder was updated in place, not duplicated")
	assert.Equal(t, firstID, notes[0].ID)
	assert.Equal(t, models.NotificationSeverityCritical, notes[0].Severity)
	assert.Contains(t, notes[0].Message, "have expired")
}

// TestSendExpiryReminders_NoEscalation_SameOrLowerSeverity_NoNoise is the
// inverse: a recheck that finds the state no worse than what's already
// standing must not touch the notification or create noise.
func TestSendExpiryReminders_NoEscalation_SameOrLowerSeverity_NoNoise(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newExpiryReminderCore(t)

	// Default fixture already has an expired secret → Critical on first run.
	sent, err := c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	require.Equal(t, 1, sent)

	var before models.Notification
	require.NoError(t, db.Where("type = ?", NotificationExpiryReminder).First(&before).Error)
	require.Equal(t, models.NotificationSeverityCritical, before.Severity)

	// Still expired (same severity), still unread: no escalation, no noise.
	sent, err = c.SendExpiryReminders(ctx, 14)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "an at-or-below-severity recheck must not notify again")

	var after models.Notification
	require.NoError(t, db.Where("type = ?", NotificationExpiryReminder).First(&after).Error)
	assert.Equal(t, before.Message, after.Message)
	assert.Equal(t, before.Severity, after.Severity)
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
