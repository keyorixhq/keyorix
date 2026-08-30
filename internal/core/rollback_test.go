package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

func rollbackCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}))
	// #1632: enforceSecretReadGuards (reached via RotateSecret) now calls
	// c.now() -- see secret_schedule_test.go's newScheduleCore for the same fix.
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}, db
}

func TestRollbackSecret(t *testing.T) {
	ctx := context.Background()
	c, db := rollbackCore(t)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "db-password", Type: "password"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("v1-secret"), EncryptionMetadata: []byte("{}"),
	}).Error)
	// Rotate to v2 (a "bad" change we'll undo).
	_, err := c.RotateSecret(ctx, 1, []byte("v2-bad"), 0, "ada")
	require.NoError(t, err)

	// Roll back to v1 → re-instated as a NEW version (v3) with v1's value.
	secret, err := c.RollbackSecret(ctx, 1, 1, 5, "ada")
	require.NoError(t, err)
	require.NotNil(t, secret)

	latest, err := c.storage.GetLatestSecretVersion(ctx, 1)
	require.NoError(t, err)
	assert.Equal(t, 3, latest.VersionNumber, "rollback appends a new version")
	assert.Equal(t, "v1-secret", string(latest.EncryptedValue), "the new version carries the old value")

	// History is append-only: v1 and v2 still exist.
	versions, err := c.storage.GetSecretVersions(ctx, 1)
	require.NoError(t, err)
	assert.Len(t, versions, 3)

	// A rollback was audited.
	var n int64
	require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventSecretRolledBack).Count(&n).Error)
	assert.Equal(t, int64(1), n)
}

func TestRollbackSecret_Errors(t *testing.T) {
	ctx := context.Background()
	c, db := rollbackCore(t)
	require.NoError(t, db.Create(&models.SecretNode{ID: 1, Name: "k", Type: "password"}).Error)
	require.NoError(t, db.Create(&models.SecretVersion{
		SecretNodeID: 1, VersionNumber: 1, EncryptedValue: []byte("v1"), EncryptionMetadata: []byte("{}"),
	}).Error)

	// Rolling back to the current (only) version is a no-op → rejected.
	_, err := c.RollbackSecret(ctx, 1, 1, 5, "ada")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already the current version")

	// An unknown version is rejected.
	_, err = c.RollbackSecret(ctx, 1, 99, 5, "ada")
	require.Error(t, err)
}
