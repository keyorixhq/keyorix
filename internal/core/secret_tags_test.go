package core

import (
	"context"
	"strings"
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

func TestSecretTags(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.AuditEvent{}, &models.Tag{}, &models.SecretTag{}))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "mallory", Email: "m@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)

	t.Run("owner sets tags, normalized (trim/lowercase/dedupe/sort)", func(t *testing.T) {
		got, err := c.SetSecretTags(ctx, secret.ID, 1, []string{" Prod ", "prod", "DB", "  ", "tier1"})
		require.NoError(t, err)
		assert.Equal(t, []string{"db", "prod", "tier1"}, got)
	})

	t.Run("owner reads them back", func(t *testing.T) {
		got, err := c.GetSecretTags(ctx, secret.ID, 1)
		require.NoError(t, err)
		assert.Equal(t, []string{"db", "prod", "tier1"}, got)
	})

	t.Run("set replaces the whole set", func(t *testing.T) {
		got, err := c.SetSecretTags(ctx, secret.ID, 1, []string{"prod"})
		require.NoError(t, err)
		assert.Equal(t, []string{"prod"}, got)
		read, _ := c.GetSecretTags(ctx, secret.ID, 1)
		assert.Equal(t, []string{"prod"}, read, "db and tier1 removed")
	})

	t.Run("clearing to empty works", func(t *testing.T) {
		got, err := c.SetSecretTags(ctx, secret.ID, 1, []string{})
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("a non-reader cannot read tags", func(t *testing.T) {
		_, err := c.GetSecretTags(ctx, secret.ID, 2)
		require.Error(t, err)
	})

	t.Run("a non-writer cannot set tags", func(t *testing.T) {
		_, err := c.SetSecretTags(ctx, secret.ID, 2, []string{"x"})
		require.Error(t, err)
	})

	t.Run("an over-long tag is rejected", func(t *testing.T) {
		_, err := c.SetSecretTags(ctx, secret.ID, 1, []string{strings.Repeat("a", 51)})
		require.Error(t, err)
	})

	t.Run("too many tags are rejected", func(t *testing.T) {
		many := make([]string, 0, 21)
		for i := 0; i < 21; i++ {
			many = append(many, "tag-"+string(rune('a'+i)))
		}
		_, err := c.SetSecretTags(ctx, secret.ID, 1, many)
		require.Error(t, err)
	})
}
