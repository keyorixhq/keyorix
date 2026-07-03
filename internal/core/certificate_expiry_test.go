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

// newCertExpiryCore sets up a real-SQLite core with one project, a project_admin
// (user 5) and a viewer (user 6), and certificate-typed secrets in various expiry
// states (each backed by a real self-signed cert in its version row).
func newCertExpiryCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.UserRole{}, &models.Project{},
		&models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.Notification{},
	))

	now := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "payments"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 2, Name: "production", ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.User{ID: 5, Username: "ada", Email: "ada@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 6, Username: "viewer", Email: "v@x.io", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "project_admin"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 2, Name: "project_viewer"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 5, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 6, RoleID: 2, ProjectID: 1}).Error)

	mkCert := func(id uint, name string, notAfter time.Time) {
		pem, _ := selfSignedPEM(t, name+".example.com", notAfter)
		require.NoError(t, db.Create(&models.SecretNode{
			ID: id, Name: name, ProjectID: 1, EnvironmentID: 2, Type: "certificate", IsSecret: true, Status: "active", CreatedAt: now,
		}).Error)
		require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: id, VersionNumber: 1, EncryptedValue: pem}).Error)
	}
	mkCert(10, "expired", now.AddDate(0, 0, -5)) // expired 5 days ago
	mkCert(11, "soon", now.AddDate(0, 0, 10))    // within the 30-day lead window
	mkCert(12, "far", now.AddDate(0, 0, 200))    // outside the lead window
	// A certificate-typed secret whose value isn't a cert — must be skipped, not error.
	require.NoError(t, db.Create(&models.SecretNode{ID: 13, Name: "broken", ProjectID: 1, EnvironmentID: 2, Type: "certificate", IsSecret: true, Status: "active"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{SecretNodeID: 13, VersionNumber: 1, EncryptedValue: []byte("not a cert")}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }}
	return c, db, now
}

func TestScanCertificateExpiry(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newCertExpiryCore(t)

	// First run: the project_admin (user 5) is notified for the expired + soon certs;
	// the viewer (6) is not; far-future and unparseable certs don't count.
	sent, err := c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, sent, "only the project admin is notified")

	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationCertificateExpiry).Find(&notes).Error)
	require.Len(t, notes, 1)
	assert.Equal(t, uint(5), notes[0].UserID)
	require.NotNil(t, notes[0].ProjectID)
	assert.Equal(t, uint(1), *notes[0].ProjectID)
	assert.Contains(t, notes[0].Message, "expired")
	assert.Contains(t, notes[0].Message, "expiring soon")
	assert.Contains(t, notes[0].Message, "payments")

	// Second run while unread: deduped.
	sent, err = c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 0, sent, "a standing unread reminder is not duplicated")

	// After reading, still-expiring certs nudge again.
	require.NoError(t, db.Model(&models.Notification{}).Where("id = ?", notes[0].ID).Update("is_read", true).Error)
	sent, err = c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, sent)
}

func TestScanCertificateExpiry_NothingDue(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newCertExpiryCore(t)
	// Remove the expired + soon certs; only the far-future and broken ones remain.
	require.NoError(t, db.Where("id IN ?", []uint{10, 11}).Delete(&models.SecretNode{}).Error)

	sent, err := c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 0, sent)
}

func TestScanCertificateExpiry_SuspendedSkipped(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newCertExpiryCore(t)
	// Suspend the expired cert; only the "soon" cert should remain countable.
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", 10).Update("status", SecretStatusSuspended).Error)

	sent, err := c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)
	assert.Equal(t, 1, sent)
	var notes []models.Notification
	require.NoError(t, db.Where("type = ?", NotificationCertificateExpiry).Find(&notes).Error)
	require.Len(t, notes, 1)
	assert.Contains(t, notes[0].Message, "expiring soon")
	assert.NotContains(t, notes[0].Message, "expired") // the only expired cert was suspended
}

func TestCertificatePosture(t *testing.T) {
	ctx := context.Background()
	c, db, _ := newCertExpiryCore(t)

	// Before any scan/inspection, no cert has a cached expiry → all "not evaluated".
	pre := c.certificatePosture(ctx, &CompliancePosture{})
	assert.Equal(t, 4, pre.TotalCertificates)
	assert.Equal(t, 4, pre.NotEvaluated)
	assert.Equal(t, 0, pre.Expired)

	// The scan caches notAfter as a side-effect; the posture then reports hygiene with
	// no decryption. expired(10)+soon(11)+far(12) parse; broken(13) stays unevaluated.
	_, err := c.ScanCertificateExpiry(ctx, 30)
	require.NoError(t, err)

	post := c.certificatePosture(ctx, &CompliancePosture{})
	assert.Equal(t, 4, post.TotalCertificates)
	assert.Equal(t, 1, post.Expired)
	assert.Equal(t, 1, post.ExpiringSoon)
	assert.Equal(t, 1, post.NotEvaluated) // only the unparseable "broken" cert

	// The cache was actually written for a parseable cert.
	var s models.SecretNode
	require.NoError(t, db.First(&s, 10).Error)
	require.NotNil(t, s.CertNotAfter)
}

func TestCertificateHygieneControl(t *testing.T) {
	// An expired certificate flips the control to a gap; none → pass.
	gap := findControl(t, EvaluateControls(&CompliancePosture{Certificates: CertificatePosture{TotalCertificates: 2, Expired: 1}}), "certificate-hygiene")
	assert.Equal(t, ControlStatusGap, gap.Status)
	assert.NotEmpty(t, gap.Frameworks.ENS)

	ok := findControl(t, EvaluateControls(&CompliancePosture{Certificates: CertificatePosture{TotalCertificates: 2, ExpiringSoon: 1}}), "certificate-hygiene")
	assert.Equal(t, ControlStatusPass, ok.Status, "expiring-soon is a warning in the detail, not a hard gap")
}

func TestCertificateExpiryMessage(t *testing.T) {
	assert.Contains(t, certificateExpiryMessage("p", 2, 3), "2 certificate(s) expired and 3 expiring soon")
	assert.Contains(t, certificateExpiryMessage("p", 2, 0), "2 certificate(s) have expired")
	assert.Contains(t, certificateExpiryMessage("p", 0, 4), "4 certificate(s) expiring soon")
}
