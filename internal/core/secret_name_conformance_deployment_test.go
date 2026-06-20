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

func TestDeploymentSecretNameConformance(t *testing.T) {
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

	// Two projects; each gets one conforming and one non-conforming name, created
	// directly via storage (i.e. before any policy existed).
	mkProject := func(name string, secretNames ...string) {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: name})
		require.NoError(t, err)
		e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
		require.NoError(t, err)
		for _, sn := range secretNames {
			_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
				Name: sn, ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
				IsSecret: true, CreatedAt: now, UpdatedAt: now,
			})
			require.NoError(t, err)
		}
	}
	mkProject("alpha", "DB_PASSWORD", "alpha-key") // alpha-key violates
	mkProject("beta", "API_TOKEN", "beta key")     // "beta key" violates (space)

	t.Run("no policy → enabled false, scan skipped, no violations", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.False(t, rep.PolicyEnabled)
		assert.Empty(t, rep.Violations)
		assert.Zero(t, rep.TotalSecrets)
	})

	t.Run("aggregates violations across all projects, each tagged with its project", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Z][A-Z0-9_]*$"}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.True(t, rep.PolicyEnabled)
		assert.Equal(t, 4, rep.TotalSecrets, "two projects × two secrets")
		require.Len(t, rep.Violations, 2)

		byName := map[string]DeploymentSecretNameViolation{}
		for _, v := range rep.Violations {
			byName[v.Name] = v
		}
		require.Contains(t, byName, "alpha-key")
		assert.Equal(t, "alpha", byName["alpha-key"].ProjectName)
		require.Contains(t, byName, "beta key")
		assert.Equal(t, "beta", byName["beta key"].ProjectName)
		assert.Contains(t, byName["beta key"].Reason, "pattern")
	})

	t.Run("when every name conforms, no violations but total counted", func(t *testing.T) {
		require.NoError(t, c.SetSecretNamePolicy(SecretNamePolicy{Enabled: true, Pattern: "^[A-Za-z0-9_ -]+$"}))
		rep, err := c.DeploymentSecretNameConformance(ctx)
		require.NoError(t, err)
		assert.Equal(t, 4, rep.TotalSecrets)
		assert.Empty(t, rep.Violations)
	})
}
