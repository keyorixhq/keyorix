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

func newSuspendFixture(t *testing.T) (*KeyorixCore, uint, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		Status: SecretStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("v"),
	})
	require.NoError(t, err)
	return c, secret.ID, db
}

func TestSuspendResumeSecret(t *testing.T) {
	ctx := context.Background()

	t.Run("suspend blocks value reads; resume restores them", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		// Readable before suspension.
		_, err := c.GetSecretValue(ctx, id)
		require.NoError(t, err)

		s, err := c.SuspendSecret(ctx, id, 1, "suspected leak")
		require.NoError(t, err)
		assert.Equal(t, SecretStatusSuspended, s.Status)

		_, err = c.GetSecretValue(ctx, id)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")
		_, err = c.GetSecretValueByVersion(ctx, id, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "suspended")

		s, err = c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, s.Status)
		_, err = c.GetSecretValue(ctx, id)
		require.NoError(t, err, "value is readable again after resume")
	})

	t.Run("suspend is idempotent and audited once", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecret(ctx, id, 1, "")
		require.NoError(t, err)
		_, err = c.SuspendSecret(ctx, id, 1, "") // no-op
		require.NoError(t, err)

		var count int64
		require.NoError(t, db.Model(&models.AuditEvent{}).Where("event_type = ?", EventSecretSuspended).Count(&count).Error)
		assert.EqualValues(t, 1, count, "re-suspending an already-suspended secret does not re-audit")
	})

	t.Run("resume on a non-suspended secret is a no-op", func(t *testing.T) {
		c, id, _ := newSuspendFixture(t)
		s, err := c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		assert.Equal(t, SecretStatusActive, s.Status)
	})
}
