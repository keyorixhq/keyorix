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

func TestSecretNameConformance(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{},
	))

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	env, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)

	// Secrets created directly via storage — i.e. BEFORE any naming policy existed, so
	// non-conforming names are present (the real scenario: a policy added/tightened later).
	mk := func(name string) {
		_, e := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: p.ID, EnvironmentID: env.ID, Type: "password", OwnerID: 1,
			IsSecret: true, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, e)
	}
	mk("DB_PASSWORD")           // conforms (UPPER_SNAKE, within length)
	mk("db-password")           // violates pattern (lowercase + hyphen)
	mk("VERY_LONG_SECRET_NAME") // conforms pattern but exceeds the length cap
	// A folder node — must be excluded (only assets have governed names).
	_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
		Name: "a folder!", ProjectID: p.ID, EnvironmentID: env.ID, IsSecret: false, CreatedAt: now, UpdatedAt: now,
	})
	require.NoError(t, err)

	t.Run("no policy configured → enabled false, no scan, no violations", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{}))
		rep, err := c.SecretNameConformance(ctx, p.ID)
		require.NoError(t, err)
		assert.False(t, rep.PolicyEnabled)
		assert.Empty(t, rep.Violations)
		assert.Zero(t, rep.TotalSecrets, "the scan is skipped when no policy is set")
	})

	t.Run("flags non-conforming names with reasons; excludes folders; sorts by name", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{
			Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$", MaxLength: 12,
		}))
		rep, err := c.SecretNameConformance(ctx, p.ID)
		require.NoError(t, err)
		assert.True(t, rep.PolicyEnabled)
		assert.Equal(t, "^[A-Z][A-Z0-9_]*$", rep.Pattern)
		assert.Equal(t, 12, rep.MaxLength)
		assert.Equal(t, 3, rep.TotalSecrets, "three secrets scanned; the folder is excluded")

		require.Len(t, rep.Violations, 2)
		// Sorted by name: "VERY_LONG_SECRET_NAME" < "db-password" (uppercase sorts first).
		assert.Equal(t, "VERY_LONG_SECRET_NAME", rep.Violations[0].Name)
		assert.Contains(t, rep.Violations[0].Reason, "maximum", "length cap is the first check")
		assert.Equal(t, "db-password", rep.Violations[1].Name)
		assert.Contains(t, rep.Violations[1].Reason, "pattern")
		assert.Equal(t, env.ID, rep.Violations[1].EnvironmentID)
	})

	t.Run("when every name conforms, violations is empty but total is counted", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{
			Enabled: true, Pattern: "^[A-Za-z0-9_-]+$", MaxLength: 100,
		}))
		rep, err := c.SecretNameConformance(ctx, p.ID)
		require.NoError(t, err)
		assert.True(t, rep.PolicyEnabled)
		assert.Equal(t, 3, rep.TotalSecrets)
		assert.Empty(t, rep.Violations)
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.SecretNameConformance(ctx, 0)
		require.Error(t, err)
	})
}
