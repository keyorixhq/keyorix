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

func TestListOrphanedSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.Project{}, &models.Environment{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// Two users: one stays, one will be offboarded.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "owner", Email: "o@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)

	// Two projects, each with an environment (the list query joins environments).
	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	mk := func(name string, projectID, envID, ownerID uint) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: ownerID, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	keep := mk("kept", p1.ID, e1.ID, 1)         // owner stays — not orphaned
	orphanA := mk("orphan-a", p1.ID, e1.ID, 2)  // owner will leave
	orphanB := mk("orphan-b", p1.ID, e1.ID, 2)  // owner will leave
	ghostOwner := mk("ghost", p1.ID, e1.ID, 99) // owner never existed
	otherProj := mk("other", p2.ID, e2.ID, 2)   // different project — excluded

	t.Run("a secret owned by a never-existent user is already orphaned", func(t *testing.T) {
		got, err := c.ListOrphanedSecrets(ctx, p1.ID)
		require.NoError(t, err)
		ids := map[uint]bool{}
		for _, s := range got {
			ids[s.ID] = true
		}
		assert.True(t, ids[ghostOwner], "owner_id 99 has no live user")
		assert.False(t, ids[keep], "live owner is not orphaned")
		assert.False(t, ids[orphanA], "owner still live until offboarded")
	})

	// Offboard user 2 (soft-delete).
	require.NoError(t, c.storage.DeleteUser(ctx, 2))

	t.Run("offboarding the owner orphans their secrets, scoped to the project", func(t *testing.T) {
		got, err := c.ListOrphanedSecrets(ctx, p1.ID)
		require.NoError(t, err)
		ids := map[uint]bool{}
		for _, s := range got {
			ids[s.ID] = true
		}
		assert.True(t, ids[orphanA])
		assert.True(t, ids[orphanB])
		assert.True(t, ids[ghostOwner])
		assert.False(t, ids[keep], "owner 1 is still live")
		assert.False(t, ids[otherProj], "other project's secret must not appear")
		assert.Len(t, got, 3)
	})

	t.Run("results are ordered by name", func(t *testing.T) {
		got, err := c.ListOrphanedSecrets(ctx, p1.ID)
		require.NoError(t, err)
		require.Len(t, got, 3)
		assert.Equal(t, "ghost", got[0].Name)
		assert.Equal(t, "orphan-a", got[1].Name)
		assert.Equal(t, "orphan-b", got[2].Name)
	})

	t.Run("a project ID of zero is rejected", func(t *testing.T) {
		_, err := c.ListOrphanedSecrets(ctx, 0)
		require.Error(t, err)
	})
}
