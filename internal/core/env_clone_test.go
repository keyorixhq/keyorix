package core

import (
	"context"
	"fmt"
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

// newCloneTestCore builds a minimal KeyorixCore backed by an isolated in-memory
// SQLite DB for environment-clone integration tests. Each call gets its own DSN
// keyed by test name to prevent cross-test DB collisions.
func newCloneTestCore(t *testing.T) *KeyorixCore {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=private", t.Name())
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Project{},
		&models.Environment{},
		&models.AuditEvent{},
		&models.SecretAccessLog{},
	))
	return &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
}

func TestCloneEnvironment_Basic(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-basic"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	// Create 3 secrets in src.
	for _, name := range []string{"alpha", "beta", "gamma"} {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("val-" + name),
			ProjectID: p.ID, EnvironmentID: src.ID,
			Type: "generic", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, "staging", result.SourceEnv)
	assert.Equal(t, "production", result.DestEnv)
	assert.Equal(t, 3, result.SecretsCloned)
	assert.Equal(t, 0, result.SecretsSkipped)
}

func TestCloneEnvironment_SkipsExisting(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-skip"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	// 3 secrets in src.
	for _, name := range []string{"db", "api", "secret3"} {
		_, err := c.CreateSecret(ctx, &CreateSecretRequest{
			Name: name, Value: []byte("v"),
			ProjectID: p.ID, EnvironmentID: src.ID,
			Type: "generic", CreatedBy: "owner", OwnerID: 1,
		})
		require.NoError(t, err)
	}
	// "db" already exists in dst.
	_, err := c.CreateSecret(ctx, &CreateSecretRequest{
		Name: "db", Value: []byte("prod-val"),
		ProjectID: p.ID, EnvironmentID: dst.ID,
		Type: "generic", CreatedBy: "owner", OwnerID: 1,
	})
	require.NoError(t, err)

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, 2, result.SecretsCloned, "api and secret3 are new")
	assert.Equal(t, 1, result.SecretsSkipped, "db already exists in dst")
	assert.Len(t, result.Errors, 1)
}

func TestCloneEnvironment_EmptySource(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-empty"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})

	result, err := c.CloneEnvironment(ctx, p.ID, src.ID, dst.ID, "owner", 1)
	require.NoError(t, err)
	assert.Equal(t, 0, result.SecretsCloned)
	assert.Equal(t, 0, result.SecretsSkipped)
}

func TestCloneEnvironment_DifferentProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p1, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-diff-1"})
	p2, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-diff-2"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p1.ID})
	dst, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})

	_, err := c.CloneEnvironment(ctx, p1.ID, src.ID, dst.ID, "owner", 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must belong to the given project")
}

func TestCloneEnvironment_DestNotFound(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	c := newCloneTestCore(t)
	ctx := context.Background()

	p, _ := c.storage.CreateProject(ctx, &models.Project{Name: "p-clone-notfound"})
	src, _ := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "staging", ProjectID: p.ID})

	_, err := c.CloneEnvironment(ctx, p.ID, src.ID, 99999, "owner", 1)
	require.Error(t, err)
}
