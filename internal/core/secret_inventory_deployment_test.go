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

func TestDeploymentSecretsInventory(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{},
	))
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", Email: "a@t.com"}).Error)

	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	mkProject := func(name string) *models.Project {
		p, err := c.storage.CreateProject(ctx, &models.Project{Name: name})
		require.NoError(t, err)
		e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
		require.NoError(t, err)
		_, err = c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name + "-key", ProjectID: p.ID, EnvironmentID: e.ID, Type: "password", OwnerID: 1,
			IsSecret: true, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return p
	}
	pa := mkProject("alpha")
	pb := mkProject("beta")

	t.Run("manifests every project's secrets, project name attached", func(t *testing.T) {
		inv, err := c.DeploymentSecretsInventory(ctx)
		require.NoError(t, err)
		require.Len(t, inv, 2)

		byProject := map[uint]DeploymentSecretInventoryItem{}
		for _, it := range inv {
			byProject[it.ProjectID] = it
		}
		assert.Equal(t, "alpha", byProject[pa.ID].ProjectName)
		assert.Equal(t, "alpha-key", byProject[pa.ID].Name)
		assert.Equal(t, "production", byProject[pa.ID].EnvironmentName)
		assert.Equal(t, "alice", byProject[pa.ID].OwnerUsername)
		assert.Equal(t, "beta", byProject[pb.ID].ProjectName)
	})
}
