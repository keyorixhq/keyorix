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

func TestSecretNamePolicy_Validate(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())

	t.Run("disabled policy passes anything", func(t *testing.T) {
		c := &KeyorixCore{}
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{}))
		assert.NoError(t, c.validateSecretName("anything goes!"))
	})

	t.Run("an invalid pattern is rejected at set time", func(t *testing.T) {
		c := &KeyorixCore{}
		err := c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "("})
		require.Error(t, err)
	})

	t.Run("pattern is enforced", func(t *testing.T) {
		c := &KeyorixCore{}
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
		assert.NoError(t, c.validateSecretName("DB_PASSWORD"))
		assert.Error(t, c.validateSecretName("db-password"), "lowercase/hyphen violates UPPER_SNAKE")
	})

	t.Run("max length is enforced", func(t *testing.T) {
		c := &KeyorixCore{}
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, MaxLength: 5}))
		assert.NoError(t, c.validateSecretName("short"))
		assert.Error(t, c.validateSecretName("toolong"))
	})
}

func TestCreateSecret_NamePolicy(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}, &models.AuditEvent{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
	ctx := context.Background()
	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	e, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	mkReq := func(name string) *CreateSecretRequest {
		return &CreateSecretRequest{
			Name: name, Value: []byte("supersecret1"), ProjectID: p.ID, EnvironmentID: e.ID,
			Type: "password", CreatedBy: "owner", OwnerID: 1,
		}
	}

	t.Run("a conforming name is accepted", func(t *testing.T) {
		_, err := c.CreateSecret(ctx, mkReq("DB_PASSWORD"))
		require.NoError(t, err)
	})

	t.Run("a non-conforming name is rejected", func(t *testing.T) {
		_, err := c.CreateSecret(ctx, mkReq("db-password"))
		require.Error(t, err)
	})
}
