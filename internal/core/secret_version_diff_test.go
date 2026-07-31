// secret_version_diff_test.go — SQLite integration tests for DiffSecretVersions.
package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newDiffCore opens an in-memory SQLite database, runs AutoMigrate for the
// tables needed by DiffSecretVersions, and returns the core + DB handle.
func newDiffCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1) // serialise access on the in-memory DB

	require.NoError(t, db.AutoMigrate(
		&models.Project{},
		&models.Environment{},
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.SecretACL{},
	))

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	return c, db
}

// seedDiffFixture inserts a project, environment, and secret node, then returns
// the secret's ID. Callers add versions manually.
func seedDiffFixture(t *testing.T, db *gorm.DB, classification string, expiry *time.Time) uint {
	t.Helper()
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "production"}).Error)
	node := &models.SecretNode{
		ID:             10,
		Name:           "my-api-key",
		ProjectID:      1,
		EnvironmentID:  1,
		IsSecret:       true,
		Type:           "password",
		Status:         "active",
		Classification: classification,
		Expiration:     expiry,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	require.NoError(t, db.Create(node).Error)
	return node.ID
}

func addVersion(t *testing.T, db *gorm.DB, secretID uint, versionNumber, readCount int) {
	t.Helper()
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID:   secretID,
		VersionNumber:  versionNumber,
		EncryptedValue: []byte("ciphertext-v" + string(rune('0'+versionNumber))),
		ReadCount:      readCount,
		CreatedAt:      time.Now(),
	}).Error)
}

// ── TestDiffSecretVersions_NoChanges ─────────────────────────────────────────

// TestDiffSecretVersions_NoChanges confirms that two versions with the same
// read count and no node-level updates return an empty Changes slice.
func TestDiffSecretVersions_NoChanges(t *testing.T) {
	c, db := newDiffCore(t)
	sid := seedDiffFixture(t, db, "internal", nil)
	addVersion(t, db, sid, 1, 5)
	addVersion(t, db, sid, 2, 5)

	// Ensure UpdatedAt == CreatedAt so no "node updated after from-version" branch fires.
	// (SQLite stores times with second precision; we just need them equal.)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", sid).
		UpdateColumn("updated_at", db.NowFunc()).Error)
	// Re-read to get the same timestamp.
	var node models.SecretNode
	require.NoError(t, db.First(&node, sid).Error)
	require.NoError(t, db.Model(&models.SecretNode{}).Where("id = ?", sid).
		UpdateColumn("updated_at", node.CreatedAt).Error)

	diff, err := c.DiffSecretVersions(context.Background(), sid, 1, 2)
	require.NoError(t, err)
	assert.Equal(t, sid, diff.SecretID)
	assert.Equal(t, "my-api-key", diff.SecretName)
	assert.Equal(t, 1, diff.FromVersion)
	assert.Equal(t, 2, diff.ToVersion)
	assert.Empty(t, diff.Changes, "no metadata should differ")
}

// ── TestDiffSecretVersions_ClassificationChanged ──────────────────────────────

// TestDiffSecretVersions_ClassificationChanged confirms that when the node's
// UpdatedAt is after the from-version's CreatedAt, a classification change is
// reported as (unknown → current).
func TestDiffSecretVersions_ClassificationChanged(t *testing.T) {
	c, db := newDiffCore(t)

	// Seed with the node's UpdatedAt set AFTER the from-version will be created,
	// simulating a classification change between versions.
	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "production"}).Error)
	node := &models.SecretNode{
		ID:             10,
		Name:           "my-api-key",
		ProjectID:      1,
		EnvironmentID:  1,
		IsSecret:       true,
		Type:           "password",
		Status:         "active",
		Classification: "confidential",
		CreatedAt:      past,
		UpdatedAt:      future, // updated after the from-version was created
	}
	require.NoError(t, db.Create(node).Error)

	// from-version created in the past (before UpdatedAt).
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 1, EncryptedValue: []byte("v1"), ReadCount: 0,
		CreatedAt: past,
	}).Error)
	// to-version created more recently.
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 2, EncryptedValue: []byte("v2"), ReadCount: 0,
		CreatedAt: future,
	}).Error)

	diff, err := c.DiffSecretVersions(context.Background(), uint(10), 1, 2)
	require.NoError(t, err)

	require.Len(t, diff.Changes, 1)
	assert.Equal(t, "classification", diff.Changes[0].Field)
	assert.Equal(t, "(unknown)", diff.Changes[0].OldValue)
	assert.Equal(t, "confidential", diff.Changes[0].NewValue)
}

// ── TestDiffSecretVersions_ExpiryAdded ────────────────────────────────────────

// TestDiffSecretVersions_ExpiryAdded confirms that when the node gained an
// expiry (UpdatedAt > from.CreatedAt) a change entry is emitted.
func TestDiffSecretVersions_ExpiryAdded(t *testing.T) {
	c, db := newDiffCore(t)

	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(1 * time.Hour)
	expiry := time.Date(2026, 12, 31, 0, 0, 0, 0, time.UTC)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "production"}).Error)
	node := &models.SecretNode{
		ID:            10,
		Name:          "my-api-key",
		ProjectID:     1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
		Expiration:    &expiry,
		CreatedAt:     past,
		UpdatedAt:     future, // updated after from-version
	}
	require.NoError(t, db.Create(node).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 1, EncryptedValue: []byte("v1"), ReadCount: 0,
		CreatedAt: past,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 2, EncryptedValue: []byte("v2"), ReadCount: 0,
		CreatedAt: future,
	}).Error)

	diff, err := c.DiffSecretVersions(context.Background(), uint(10), 1, 2)
	require.NoError(t, err)

	// Should have an expiry change (old = "(unknown)", new = "2026-12-31").
	var expiryChange *SecretVersionChange
	for i := range diff.Changes {
		if diff.Changes[i].Field == "expiry" {
			expiryChange = &diff.Changes[i]
			break
		}
	}
	require.NotNil(t, expiryChange, "expected an expiry change")
	assert.Equal(t, "(unknown)", expiryChange.OldValue)
	assert.Equal(t, "2026-12-31", expiryChange.NewValue)
}

// ── TestDiffSecretVersions_MultipleChanges ────────────────────────────────────

// TestDiffSecretVersions_MultipleChanges confirms that both a classification
// change and a read_count delta are reported when both differ.
func TestDiffSecretVersions_MultipleChanges(t *testing.T) {
	c, db := newDiffCore(t)

	past := time.Now().Add(-2 * time.Hour)
	future := time.Now().Add(1 * time.Hour)

	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "production"}).Error)
	node := &models.SecretNode{
		ID:             10,
		Name:           "my-api-key",
		ProjectID:      1,
		EnvironmentID:  1,
		IsSecret:       true,
		Type:           "password",
		Status:         "active",
		Classification: "confidential",
		CreatedAt:      past,
		UpdatedAt:      future,
	}
	require.NoError(t, db.Create(node).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 1, EncryptedValue: []byte("v1"), ReadCount: 3,
		CreatedAt: past,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 2, EncryptedValue: []byte("v2"), ReadCount: 47,
		CreatedAt: future,
	}).Error)

	diff, err := c.DiffSecretVersions(context.Background(), uint(10), 1, 2)
	require.NoError(t, err)

	fields := make(map[string]SecretVersionChange, len(diff.Changes))
	for _, ch := range diff.Changes {
		fields[ch.Field] = ch
	}

	assert.Contains(t, fields, "classification", "classification change expected")
	assert.Contains(t, fields, "read_count_delta", "read_count_delta change expected")
	assert.Equal(t, "3", fields["read_count_delta"].OldValue)
	assert.Contains(t, fields["read_count_delta"].NewValue, "47")
}

// ── TestDiffSecretVersions_InvalidVersion ─────────────────────────────────────

// TestDiffSecretVersions_InvalidVersion confirms that requesting a non-existent
// version number returns an error.
func TestDiffSecretVersions_InvalidVersion(t *testing.T) {
	c, db := newDiffCore(t)
	sid := seedDiffFixture(t, db, "", nil)
	addVersion(t, db, sid, 1, 0)

	_, err := c.DiffSecretVersions(context.Background(), sid, 1, 99)
	require.Error(t, err, "version 99 does not exist → error expected")
}

// ── TestDiffSecretVersions_ZeroSecretID ──────────────────────────────────────

// TestDiffSecretVersions_ZeroSecretID confirms that secretID==0 is rejected
// with a validation error.
func TestDiffSecretVersions_ZeroSecretID(t *testing.T) {
	c, _ := newDiffCore(t)
	_, err := c.DiffSecretVersions(context.Background(), 0, 1, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

// ── TestDiffSecretVersions_ZeroVersions ──────────────────────────────────────

// TestDiffSecretVersions_ZeroVersions confirms that non-positive version
// numbers are rejected with a validation error.
func TestDiffSecretVersions_ZeroVersions(t *testing.T) {
	c, _ := newDiffCore(t)

	_, err := c.DiffSecretVersions(context.Background(), 1, 0, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version numbers must be positive")

	_, err = c.DiffSecretVersions(context.Background(), 1, 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "version numbers must be positive")
}

// ── TestDiffSecretVersions_SameVersion ───────────────────────────────────────

// TestDiffSecretVersions_SameVersion confirms that from==to is rejected.
func TestDiffSecretVersions_SameVersionCore(t *testing.T) {
	c, _ := newDiffCore(t)
	_, err := c.DiffSecretVersions(context.Background(), 1, 3, 3)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must differ")
}

// ── TestDiffSecretVersions_SecretNotFound ─────────────────────────────────────

// TestDiffSecretVersions_SecretNotFound confirms that a missing secret node
// surfaces as an error.
func TestDiffSecretVersions_SecretNotFound(t *testing.T) {
	c, _ := newDiffCore(t)
	_, err := c.DiffSecretVersions(context.Background(), 9999, 1, 2)
	require.Error(t, err)
}

// ── TestDiffSecretVersions_FromVersionNotFound ────────────────────────────────

// TestDiffSecretVersions_FromVersionNotFound confirms that a missing FROM
// version number returns an error (covers the error path after GetSecretVersion
// for the from-version).
func TestDiffSecretVersions_FromVersionNotFound(t *testing.T) {
	c, db := newDiffCore(t)
	sid := seedDiffFixture(t, db, "", nil)
	// Only seed version 2; version 1 does not exist.
	addVersion(t, db, sid, 2, 0)

	_, err := c.DiffSecretVersions(context.Background(), sid, 1, 2)
	require.Error(t, err, "from version 1 does not exist → error expected")
}

// ── TestDiffSecretVersions_WithACLEntries ─────────────────────────────────────

// TestDiffSecretVersions_WithACLEntries seeds an ACL entry for the secret and
// confirms that the ACLUserIDs slice is populated (covers the ACL loop body).
func TestDiffSecretVersions_WithACLEntries(t *testing.T) {
	c, db := newDiffCore(t)
	sid := seedDiffFixture(t, db, "", nil)
	addVersion(t, db, sid, 1, 0)
	addVersion(t, db, sid, 2, 0)

	// Seed an ACL entry for user 42.
	require.NoError(t, db.Create(&models.SecretACL{
		SecretID:    sid,
		UserID:      42,
		Permissions: `["secrets.read"]`,
		GrantedBy:   1,
	}).Error)

	diff, err := c.DiffSecretVersions(context.Background(), sid, 1, 2)
	require.NoError(t, err)
	assert.Contains(t, diff.ACLUserIDs, uint(42), "ACL entry for user 42 must appear in the result")
}

// ── TestDiffSecretVersions_NegativeDelta ─────────────────────────────────────

// TestDiffSecretVersions_NegativeDelta exercises the branch where to.ReadCount <
// from.ReadCount (delta < 0 → sign should be "" not "+").
func TestDiffSecretVersions_NegativeDelta(t *testing.T) {
	c, db := newDiffCore(t)

	past := time.Now().Add(-2 * time.Hour)
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "production"}).Error)
	node := &models.SecretNode{
		ID:            10,
		Name:          "my-api-key",
		ProjectID:     1,
		EnvironmentID: 1,
		IsSecret:      true,
		Type:          "password",
		Status:        "active",
		CreatedAt:     past,
		UpdatedAt:     past, // no node update → no classification/expiry change
	}
	require.NoError(t, db.Create(node).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 1, EncryptedValue: []byte("v1"), ReadCount: 10,
		CreatedAt: past,
	}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 10, VersionNumber: 2, EncryptedValue: []byte("v2"), ReadCount: 3,
		CreatedAt: past,
	}).Error)

	diff, err := c.DiffSecretVersions(context.Background(), uint(10), 1, 2)
	require.NoError(t, err)

	var rc *SecretVersionChange
	for i := range diff.Changes {
		if diff.Changes[i].Field == "read_count_delta" {
			rc = &diff.Changes[i]
			break
		}
	}
	require.NotNil(t, rc, "expected a read_count_delta change")
	assert.Equal(t, "10", rc.OldValue)
	// Negative delta: sign should be "" (no "+"), value should start with "3"
	assert.True(t, len(rc.NewValue) > 0 && rc.NewValue[0] == '3', "new value starts with to.ReadCount")
	assert.NotContains(t, rc.NewValue, "+", "negative delta must not have a '+' sign")
}

// ── TestEmptyOr_EmptyString ───────────────────────────────────────────────────

// TestEmptyOr_EmptyString exercises the emptyOr("") branch that returns "(none)".
func TestEmptyOr_EmptyString(t *testing.T) {
	assert.Equal(t, "(none)", emptyOr(""))
	assert.Equal(t, "(none)", emptyOr("   "))
	assert.Equal(t, "hello", emptyOr("hello"))
}
