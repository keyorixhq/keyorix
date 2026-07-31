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

// newPolicyEnforceFixture builds an in-memory core with the value policy enabled
// (reject common) plus a project, environment, and an existing secret.
func newPolicyEnforceFixture(t *testing.T) (*KeyorixCore, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	c.SetSecretValuePolicy(SecretValuePolicy{Enabled: true, RejectCommon: true, MinLength: 6})
	ctx := context.Background()
	proj, err := c.storage.CreateProject(ctx, &models.Project{Name: "p"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
	require.NoError(t, err)
	secret, err := c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "db", ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return c, proj.ID, secret.ID
}

func TestSecretValuePolicy_EnforcedOnAllWritePaths(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateSecret rejects a weak value", func(t *testing.T) {
		c, projID, _ := newPolicyEnforceFixture(t)
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: "new", Value: []byte("changeme"), ProjectID: projID, EnvironmentID: 1, Type: "password", CreatedBy: "u",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weak or placeholder")
	})

	t.Run("RotateSecret rejects a weak value", func(t *testing.T) {
		c, _, secretID := newPolicyEnforceFixture(t)
		_, err := c.RotateSecret(ctx, secretID, []byte("password"), "u")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "weak or placeholder")
	})

	t.Run("UpdateSecret rejects a weak value (the closed bypass)", func(t *testing.T) {
		c, _, secretID := newPolicyEnforceFixture(t)
		_, err := c.UpdateSecret(ctx, &UpdateSecretRequest{ID: secretID, Value: []byte("short"), UpdatedBy: "u"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "minimum")
	})

	t.Run("UpdateSecret with a strong value succeeds", func(t *testing.T) {
		c, _, secretID := newPolicyEnforceFixture(t)
		_, err := c.UpdateSecret(ctx, &UpdateSecretRequest{ID: secretID, Value: []byte("a-strong-enough-value"), UpdatedBy: "u"})
		require.NoError(t, err)
	})

	t.Run("UpdateSecret with no value change is unaffected", func(t *testing.T) {
		c, _, secretID := newPolicyEnforceFixture(t)
		mr := 5
		_, err := c.UpdateSecret(ctx, &UpdateSecretRequest{ID: secretID, MaxReads: &mr, UpdatedBy: "u"})
		require.NoError(t, err)
	})
}
