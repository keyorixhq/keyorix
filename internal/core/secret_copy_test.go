package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestCopySecret(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p1, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	staging, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	prod, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	p2, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	otherEnv, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})

	src, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db-url", Value: []byte("postgres://secret"), ProjectID: p1.ID, EnvironmentID: staging.ID,
		Type: "connection-string", Classification: "confidential", Description: "the prod DB",
		CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	t.Run("copies value + metadata into the target environment", func(t *testing.T) {
		copied, err := c.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1)
		require.NoError(t, err)
		assert.NotEqual(t, src.ID, copied.ID, "a distinct new secret")
		assert.Equal(t, "db-url", copied.Name)
		assert.Equal(t, prod.ID, copied.EnvironmentID)
		assert.Equal(t, "connection-string", copied.Type)
		assert.Equal(t, "confidential", copied.Classification)
		assert.Equal(t, "the prod DB", copied.Description)
		assert.Equal(t, uint(1), copied.OwnerID)

		// The value carried over.
		val, err := c.GetSecretValueWithPermissionCheck(ctx, copied.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, "postgres://secret", string(val))
	})

	t.Run("a new name can be given", func(t *testing.T) {
		copied, err := c.CopySecret(ctx, src.ID, prod.ID, "db-url-renamed", "owner", 1)
		require.NoError(t, err)
		assert.Equal(t, "db-url-renamed", copied.Name)
	})

	t.Run("copying to an environment in another project is rejected", func(t *testing.T) {
		_, err := c.CopySecret(ctx, src.ID, otherEnv.ID, "", "owner", 1)
		require.Error(t, err)
	})

	t.Run("a duplicate name in the target environment is rejected", func(t *testing.T) {
		// "db-url" already copied into prod above.
		_, err := c.CopySecret(ctx, src.ID, prod.ID, "", "owner", 1)
		require.Error(t, err)
	})

	t.Run("required IDs are validated", func(t *testing.T) {
		_, err := c.CopySecret(ctx, 0, prod.ID, "", "owner", 1)
		require.Error(t, err)
		_, err = c.CopySecret(ctx, src.ID, 0, "", "owner", 1)
		require.Error(t, err)
	})
}
