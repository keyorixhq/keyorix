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

// newRenderFixture builds an in-memory core with a project, a "production"
// environment, and a secret "db-password"=s3cr3t owned by user 1.
func newRenderFixture(t *testing.T) (*KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{},
		&models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@test.com"}).Error)

	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "payments"})
	require.NoError(t, err)
	env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := st.CreateSecret(ctx, &models.SecretNode{
		Name: "db-password", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
		OwnerID: 1, IsSecret: true, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	_, err = st.CreateSecretVersion(ctx, &models.SecretVersion{
		SecretNodeID: secret.ID, VersionNumber: 1, EncryptedValue: []byte("s3cr3t"),
	})
	require.NoError(t, err)
	return c, proj.ID
}

func TestRenderSecretTemplate(t *testing.T) {
	ctx := context.Background()
	c, projectID := newRenderFixture(t)

	t.Run("expands a known reference", func(t *testing.T) {
		out, err := c.RenderSecretTemplate(ctx, "DB=${secret:production/db-password}", projectID, 1)
		require.NoError(t, err)
		assert.Equal(t, "DB=s3cr3t", out)
	})

	t.Run("unknown environment fails", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "${secret:staging/db-password}", projectID, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "environment")
	})

	t.Run("unknown secret fails", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/nope}", projectID, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("non-reader cannot resolve", func(t *testing.T) {
		// User 2 owns nothing and has no share → the per-secret read check denies.
		_, err := c.RenderSecretTemplate(ctx, "${secret:production/db-password}", projectID, 2)
		require.Error(t, err)
	})

	t.Run("requires project + user", func(t *testing.T) {
		_, err := c.RenderSecretTemplate(ctx, "x", 0, 1)
		require.Error(t, err)
		_, err = c.RenderSecretTemplate(ctx, "x", projectID, 0)
		require.Error(t, err)
	})
}
