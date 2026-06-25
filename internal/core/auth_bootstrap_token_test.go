package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// freshBootstrapCore returns a non-bootstrapped core over an in-memory store.
func freshBootstrapCore(t *testing.T) *KeyorixCore {
	t.Helper()
	require.NoError(t, i18n.Initialize(&config.Config{
		Locale: config.LocaleConfig{Language: "en", FallbackLanguage: "en"},
	}))
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db))
}

func strongBootstrapReq(token string) *BootstrapRequest {
	return &BootstrapRequest{
		Username: "admin", Email: "admin@example.com",
		Password: "BootstrapPass123!", DisplayName: "Admin", Token: token,
	}
}

// TestBootstrapSystem_TokenGate pins the fix for the unauthenticated first-admin-claim
// race: /system/init must refuse unless the caller presents the configured token.
func TestBootstrapSystem_TokenGate(t *testing.T) {
	t.Run("refuses when no server token is configured (fail closed)", func(t *testing.T) {
		c := freshBootstrapCore(t) // no SetBootstrapToken
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("anything"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")
		// Nothing was seeded.
		needs, nerr := c.SystemNeedsBootstrap(context.Background())
		require.NoError(t, nerr)
		assert.True(t, needs, "no admin should exist after a refused bootstrap")
	})

	t.Run("refuses a wrong token", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("wrong-token"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid bootstrap token")
		needs, _ := c.SystemNeedsBootstrap(context.Background())
		assert.True(t, needs)
	})

	t.Run("refuses a weak admin password even with the right token", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		req := strongBootstrapReq("correct-token")
		req.Password = "admin" // below the default policy floor
		_, err := c.BootstrapSystem(context.Background(), req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password must")
	})

	t.Run("succeeds with the right token and a strong password", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		res, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("correct-token"))
		require.NoError(t, err)
		require.NotNil(t, res.User)
		assert.False(t, res.AlreadyInitialized)
	})

	t.Run("idempotent repeat needs no token once initialised", func(t *testing.T) {
		c := freshBootstrapCore(t)
		c.SetBootstrapToken("correct-token")
		_, err := c.BootstrapSystem(context.Background(), strongBootstrapReq("correct-token"))
		require.NoError(t, err)
		// A second call with no token returns the existing state, not an error.
		res, err := c.BootstrapSystem(context.Background(), &BootstrapRequest{})
		require.NoError(t, err)
		assert.True(t, res.AlreadyInitialized)
	})
}
