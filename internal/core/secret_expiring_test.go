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

func TestListExpiringSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.Project{}, &models.Environment{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()
	now := time.Now()

	p, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	mk := func(name string, projectID, envID uint, exp *time.Time) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: 1, IsSecret: true,
			Expiration: exp, CreatedAt: now, UpdatedAt: now,
		})
		require.NoError(t, err)
		return s.ID
	}

	expired := now.Add(-2 * 24 * time.Hour)
	soon := now.Add(10 * 24 * time.Hour)
	far := now.Add(100 * 24 * time.Hour)

	expiredID := mk("expired", p.ID, e.ID, &expired)
	soonID := mk("soon", p.ID, e.ID, &soon)
	_ = mk("far", p.ID, e.ID, &far)      // outside a 30d window
	_ = mk("never", p.ID, e.ID, nil)     // no expiration
	_ = mk("other", p2.ID, e2.ID, &soon) // different project

	t.Run("lists expiring/expired within the window, soonest-first, project-scoped", func(t *testing.T) {
		got, err := c.ListExpiringSecrets(ctx, p.ID, 30)
		require.NoError(t, err)
		require.Len(t, got, 2, "expired + soon; far/never/other-project excluded")
		assert.Equal(t, expiredID, got[0].ID, "already-expired leads")
		assert.Equal(t, soonID, got[1].ID)
	})

	t.Run("a wider window includes the far one", func(t *testing.T) {
		got, err := c.ListExpiringSecrets(ctx, p.ID, 200)
		require.NoError(t, err)
		assert.Len(t, got, 3)
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.ListExpiringSecrets(ctx, 0, 30)
		require.Error(t, err)
	})

	t.Run("non-positive window falls back to the default (30d)", func(t *testing.T) {
		got, err := c.ListExpiringSecrets(ctx, p.ID, 0)
		require.NoError(t, err)
		assert.Len(t, got, 2)
	})
}
