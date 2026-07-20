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

// bulkRotateDB sets up an in-memory SQLite DB with the tables needed for bulk rotation
// tests and returns a core + a helper to create test secrets.
func bulkRotateDB(t *testing.T) (*KeyorixCore, func(name, classification string, autoRotate bool) uint) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_journal_mode=WAL"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.Project{}, &models.Environment{},
		&models.SecretNode{}, &models.SecretVersion{},
		&models.AuditEvent{}, &models.SecretAccessLog{},
	))

	ctx := context.Background()
	ls := store.NewLocalStorage(db)

	p, err := ls.CreateProject(ctx, &models.Project{Name: "bulk-rotate-proj"})
	require.NoError(t, err)
	env, err := ls.CreateEnvironment(ctx, &models.Environment{Name: "prod", ProjectID: p.ID})
	require.NoError(t, err)

	c := &KeyorixCore{storage: ls, now: time.Now}

	mk := func(name, classification string, autoRotate bool) uint {
		s, err := ls.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: env.ID,
			Type: "password", IsSecret: true, Status: "active",
			Classification: classification,
			AutoRotate:     autoRotate,
			OwnerID:        1, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		// Seed an initial version so RotateSecret can get the latest version.
		_, err = ls.CreateSecretVersion(ctx, &models.SecretVersion{
			SecretNodeID: s.ID, VersionNumber: 1,
			EncryptedValue:     []byte("initial-value"),
			EncryptionMetadata: []byte("{}"),
			CreatedAt:          time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	return c, mk
}

func TestBulkRotateSecrets_ByIDs(t *testing.T) {
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	id1 := mk("secret-alpha", "", true)
	id2 := mk("secret-beta", "", true)
	id3 := mk("secret-gamma", "", true)

	// Determine project ID from one of the secrets.
	s, err := c.storage.GetSecret(ctx, id1)
	require.NoError(t, err)
	projectID := s.ProjectID

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{id1, id2, id3},
		RotatedBy: "alice",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, result.Total)
	assert.Len(t, result.Triggered, 3)
	assert.Empty(t, result.Failed)
	assert.Contains(t, result.Triggered, id1)
	assert.Contains(t, result.Triggered, id2)
	assert.Contains(t, result.Triggered, id3)

	// Each secret now has version 2.
	for _, id := range []uint{id1, id2, id3} {
		latest, err := c.storage.GetLatestSecretVersion(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.VersionNumber, "secret %d should have been rotated to version 2", id)
	}
}

func TestBulkRotateSecrets_ByProject(t *testing.T) {
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	id1 := mk("proj-secret-a", "", true)
	id2 := mk("proj-secret-b", "", true)

	s, err := c.storage.GetSecret(ctx, id1)
	require.NoError(t, err)
	projectID := s.ProjectID

	// No SecretIDs — rotate all in the project.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	// Total includes all secrets in the project from this and the parent test helpers
	// (each helper call creates its own DB, so total here is exactly 2).
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 2)
	assert.Empty(t, result.Failed)
	assert.Contains(t, result.Triggered, id1)
	assert.Contains(t, result.Triggered, id2)
}

func TestBulkRotateSecrets_ByClassification(t *testing.T) {
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	confID := mk("conf-secret", "confidential", true)
	_ = mk("public-secret", "public", true)

	s, err := c.storage.GetSecret(ctx, confID)
	require.NoError(t, err)
	projectID := s.ProjectID

	// Filter by classification — only "confidential" should be rotated.
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID:      projectID,
		Classification: "confidential",
		RotatedBy:      "incident-response",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total, "only the confidential secret matches the filter")
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, confID, result.Triggered[0])
	assert.Empty(t, result.Failed)

	// The public secret is still on version 1.
}

func TestBulkRotateSecrets_SkipsNoConfig(t *testing.T) {
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	withRotation := mk("has-rotation", "", true)
	noRotation := mk("no-rotation", "", false)

	s, err := c.storage.GetSecret(ctx, withRotation)
	require.NoError(t, err)
	projectID := s.ProjectID

	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		RotatedBy: "ops",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Total)
	assert.Len(t, result.Triggered, 1)
	assert.Equal(t, withRotation, result.Triggered[0])
	require.Len(t, result.Failed, 1)
	assert.Equal(t, noRotation, result.Failed[0].SecretID)
	assert.Contains(t, result.Failed[0].Error, "no rotation config")

	// The no-rotation secret is still on version 1 — not an error, just a skip.
	latest, err := c.storage.GetLatestSecretVersion(ctx, noRotation)
	require.NoError(t, err)
	assert.Equal(t, 1, latest.VersionNumber)
}

func TestBulkRotateSecrets_PartialFailure(t *testing.T) {
	c, mk := bulkRotateDB(t)
	ctx := context.Background()

	valid1 := mk("valid-one", "", true)
	valid2 := mk("valid-two", "", true)
	noconf := mk("no-conf", "", false)

	s, err := c.storage.GetSecret(ctx, valid1)
	require.NoError(t, err)
	projectID := s.ProjectID

	// Mix of valid IDs + an ID that doesn't exist + one with no rotation config.
	const missingID = uint(99999)
	result, err := c.BulkRotateSecrets(ctx, BulkRotateRequest{
		ProjectID: projectID,
		SecretIDs: []uint{valid1, valid2, noconf, missingID},
		RotatedBy: "responder",
	})
	require.NoError(t, err)

	assert.Equal(t, 4, result.Total)
	// 2 succeeded, 2 failed (no-conf + missing).
	assert.Len(t, result.Triggered, 2)
	assert.Len(t, result.Failed, 2)

	failedIDs := make(map[uint]string, len(result.Failed))
	for _, f := range result.Failed {
		failedIDs[f.SecretID] = f.Error
	}
	assert.Contains(t, failedIDs[noconf], "no rotation config")
	assert.Contains(t, failedIDs[missingID], "not found")

	// valid1 and valid2 were rotated to version 2.
	for _, id := range []uint{valid1, valid2} {
		latest, err := c.storage.GetLatestSecretVersion(ctx, id)
		require.NoError(t, err)
		assert.Equal(t, 2, latest.VersionNumber)
	}
	// no-conf stays at version 1.
	latest, err := c.storage.GetLatestSecretVersion(ctx, noconf)
	require.NoError(t, err)
	assert.Equal(t, 1, latest.VersionNumber)
}
