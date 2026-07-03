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

// TestCreateSecret_AppliesTags guards #390: CreateSecretRequest.Tags was silently
// accepted and dropped — CreateSecret never read req.Tags or called SetSecretTags,
// despite both the HTTP and gRPC handlers passing the field through, so a caller
// intending an immediate "reviewed"/"exempt"-style tag at creation time got no tag
// and no error.
func TestCreateSecret_AppliesTags(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{},
		&models.Environment{}, &models.AuditEvent{}, &models.Tag{}, &models.SecretTag{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	t.Run("tags supplied at create time are persisted, normalized", func(t *testing.T) {
		created, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "DB_PASSWORD", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1, Tags: []string{" Reviewed ", "REVIEWED", "exempt"},
		})
		require.NoError(t, err)
		got, err := c.storage.GetSecretTags(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, []string{"exempt", "reviewed"}, got)
	})

	t.Run("no tags is still a no-op, no error", func(t *testing.T) {
		created, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "API_KEY", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
		got, err := c.storage.GetSecretTags(ctx, created.ID)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("an over-long tag at create time is rejected before the secret is persisted", func(t *testing.T) {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "BAD_TAG_SECRET", Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1, Tags: []string{strings.Repeat("a", 51)},
		})
		require.Error(t, err)
		_, getErr := c.storage.GetSecretByName(ctx, "BAD_TAG_SECRET", p.ID, e.ID)
		require.Error(t, getErr, "the secret must not have been created when its tag list is invalid")
	})
}
