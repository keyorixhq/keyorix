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

func rotationExecCore(t *testing.T) (*KeyorixCore, *gorm.DB, time.Time) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.RotationPolicy{}, &models.AuditEvent{},
		&models.Project{}, &models.Environment{},
	))
	// ListSecrets(ProjectID) JOINs environments, so the scope needs a real env row.
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "proj"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "prod"}).Error)
	c := &KeyorixCore{storage: store.NewLocalStorage(db)}
	fixed := time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return fixed }
	return c, db, fixed
}

func seedRotatableSecret(t *testing.T, db *gorm.DB, id uint, name string, autoRotate bool, lastRotated time.Time) {
	t.Helper()
	lr := lastRotated
	require.NoError(t, db.Create(&models.SecretNode{
		ID: id, Name: name, ProjectID: 1, EnvironmentID: 1, IsSecret: true,
		Status: "active", AutoRotate: autoRotate, LastRotatedAt: &lr, CreatedAt: lastRotated,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: id, VersionNumber: 1, EncryptedValue: []byte("original-" + name),
		EncryptionMetadata: []byte("{}"), CreatedAt: lastRotated,
	}).Error)
}

func latestVersion(t *testing.T, db *gorm.DB, secretID uint) *models.SecretVersion {
	t.Helper()
	var v models.SecretVersion
	require.NoError(t, db.Where("secret_node_id = ?", secretID).Order("version_number desc").First(&v).Error)
	return &v
}

func TestRunAutoRotation_RotatesOverdueOptedInOnly(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)

	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))   // overdue + opted-in → rotate
	seedRotatableSecret(t, db, 2, "fresh-managed", true, fixed.Add(-5*24*time.Hour))  // opted-in but not due → skip
	seedRotatableSecret(t, db, 3, "due-external", false, fixed.Add(-60*24*time.Hour)) // overdue but not opted-in → skip

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 1, n, "only the overdue, opted-in secret rotates")

	// s1: new version with a freshly generated (different) value; LastRotatedAt advanced.
	v1 := latestVersion(t, db, 1)
	assert.Equal(t, 2, v1.VersionNumber, "due-managed secret gained a new version")
	assert.NotEqual(t, "original-due-managed", string(v1.EncryptedValue))
	assert.Len(t, string(v1.EncryptedValue), rotatedValueLength)
	var s1 models.SecretNode
	require.NoError(t, db.First(&s1, 1).Error)
	require.NotNil(t, s1.LastRotatedAt)
	assert.True(t, s1.LastRotatedAt.After(fixed.Add(-time.Minute)), "LastRotatedAt advanced to now")

	// s2 and s3 are untouched (still on version 1).
	assert.Equal(t, 1, latestVersion(t, db, 2).VersionNumber, "not-due secret unchanged")
	assert.Equal(t, 1, latestVersion(t, db, 3).VersionNumber, "non-opted-in secret unchanged")
}

func TestRunAutoRotation_InactivePolicyIgnored(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "off", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// GORM applies the column default (is_active=true) for a zero-value bool on Create,
	// so force it false explicitly to model an inactive policy.
	require.NoError(t, db.Model(&models.RotationPolicy{}).Where("id = ?", 1).Update("is_active", false).Error)
	seedRotatableSecret(t, db, 1, "due-managed", true, fixed.Add(-60*24*time.Hour))

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 0, n, "no rotation under an inactive policy")
	assert.Equal(t, 1, latestVersion(t, db, 1).VersionNumber)
}

func TestSetSecretAutoRotate_TogglesAndPersists(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))

	// Enable with a generator spec.
	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, true, 48, "hex", 9))
	var s models.SecretNode
	require.NoError(t, db.First(&s, 1).Error)
	assert.True(t, s.AutoRotate)
	assert.Equal(t, 48, s.RotationLength)
	assert.Equal(t, "hex", s.RotationCharset)

	require.NoError(t, c.SetSecretAutoRotate(context.Background(), 1, false, 0, "", 9))
	require.NoError(t, db.First(&s, 1).Error)
	assert.False(t, s.AutoRotate)
}

func TestSetSecretAutoRotate_ValidatesSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	seedRotatableSecret(t, db, 1, "key", false, fixed.Add(-24*time.Hour))
	ctx := context.Background()

	err := c.SetSecretAutoRotate(ctx, 1, true, 0, "klingon", 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown rotation charset")

	err = c.SetSecretAutoRotate(ctx, 1, true, 5000, "", 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out of range")
}

func TestGenerateRotatedValueSpec_LengthAndCharset(t *testing.T) {
	// hex charset, custom length.
	v, err := generateRotatedValueSpec(48, "hex")
	require.NoError(t, err)
	assert.Len(t, v, 48)
	for _, ch := range v {
		assert.Contains(t, charsetHex, string(ch))
	}
	// length 0 → default; unknown charset → alphanumeric (fail-safe, never empty).
	v, err = generateRotatedValueSpec(0, "bogus")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueLength)
	for _, ch := range v {
		assert.Contains(t, charsetAlphanumeric, string(ch))
	}
	// below-min length clamps up, not to zero-length.
	v, err = generateRotatedValueSpec(2, "")
	require.NoError(t, err)
	assert.Len(t, v, rotatedValueMinLength)
}

// The executor honors a secret's generator spec.
func TestRunAutoRotation_UsesSecretSpec(t *testing.T) {
	c, db, fixed := rotationExecCore(t)
	pid := uint(1)
	require.NoError(t, db.Create(&models.RotationPolicy{
		ID: 1, Name: "30-day", Scope: "project", ProjectID: &pid, IntervalDays: 30,
		IsActive: true, CreatedBy: "admin",
	}).Error)
	// Overdue, opted-in, hex/16.
	lr := fixed.Add(-60 * 24 * time.Hour)
	require.NoError(t, db.Create(&models.SecretNode{
		ID: 1, Name: "hex-key", ProjectID: 1, EnvironmentID: 1, IsSecret: true, Status: "active",
		AutoRotate: true, RotationLength: 16, RotationCharset: "hex", LastRotatedAt: &lr, CreatedAt: lr,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("orig"), EncryptionMetadata: []byte("{}"), CreatedAt: lr,
	}).Error)

	n, err := c.RunAutoRotation(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, n)

	v := latestVersion(t, db, 1)
	assert.Equal(t, 2, v.VersionNumber)
	assert.Len(t, string(v.EncryptedValue), 16)
	for _, ch := range string(v.EncryptedValue) {
		assert.Contains(t, charsetHex, string(ch))
	}
}

func TestGenerateRotatedValue_UniqueAndCharset(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		v, err := generateRotatedValue()
		require.NoError(t, err)
		assert.Len(t, v, rotatedValueLength)
		for _, ch := range v {
			assert.Contains(t, rotatedValueCharset, string(ch))
		}
		assert.False(t, seen[v], "values must not repeat")
		seen[v] = true
	}
}
