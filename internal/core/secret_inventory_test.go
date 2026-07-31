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

func TestSecretsInventory(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{},
		&models.Environment{}, &models.SecretAccessLog{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	prod, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	dev, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "development", ProjectID: p.ID})
	require.NoError(t, err)

	exp := now.Add(48 * time.Hour)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db-pass", ProjectID: p.ID, EnvironmentID: prod.ID, Type: "password", OwnerID: 1,
		Classification: "confidential", IsSecret: true, Expiration: &exp, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "api-key", ProjectID: p.ID, EnvironmentID: dev.ID, Type: "api_key", OwnerID: 1,
		IsSecret: true, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)
	// A folder node — must be excluded from the inventory.
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "folder", ProjectID: p.ID, EnvironmentID: dev.ID, IsSecret: false, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	t.Run("lists secret metadata, excludes folders, resolves names, sorts by env then name", func(t *testing.T) {
		inv, err := c.SecretsInventory(ctx, p.ID)
		require.NoError(t, err)
		require.Len(t, inv, 2, "two secrets; the folder is excluded")

		// Sorted by environment (development < production) then name.
		assert.Equal(t, "development", inv[0].EnvironmentName)
		assert.Equal(t, "api-key", inv[0].Name)
		assert.Equal(t, "alice", inv[0].OwnerUsername)

		assert.Equal(t, "production", inv[1].EnvironmentName)
		assert.Equal(t, "db-pass", inv[1].Name)
		assert.Equal(t, "confidential", inv[1].Classification)
		require.NotNil(t, inv[1].Expiration)
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.SecretsInventory(ctx, 0)
		require.Error(t, err)
	})
}
