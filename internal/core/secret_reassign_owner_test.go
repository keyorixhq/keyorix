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

func TestReassignOwnedSecrets(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{}, &models.AuditEvent{}, &models.Project{}, &models.Environment{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{}))
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: time.Now}
	ctx := context.Background()

	// admin (actor), leaver (departing owner), heir (new owner), bystander.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "a@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "leaver", Email: "l@t.com"}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "heir", Email: "h@t.com"}).Error)

	p1, err := c.storage.CreateProject(ctx, &models.Project{Name: "p1"})
	require.NoError(t, err)
	e1, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p1.ID})
	require.NoError(t, err)
	p2, err := c.storage.CreateProject(ctx, &models.Project{Name: "p2"})
	require.NoError(t, err)
	e2, err := c.storage.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: p2.ID})
	require.NoError(t, err)

	// The heir must have access to the secrets' scope to become their owner.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 1, ProjectID: p1.ID}).Error)

	mk := func(name string, projectID, envID, ownerID uint) uint {
		s, err := c.storage.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: projectID, EnvironmentID: envID, Type: "password", OwnerID: ownerID, IsSecret: true,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s.ID
	}

	a := mk("a", p1.ID, e1.ID, 2)         // leaver's
	b := mk("b", p1.ID, e1.ID, 2)         // leaver's
	keep := mk("keep", p1.ID, e1.ID, 1)   // admin's — untouched
	other := mk("other", p2.ID, e2.ID, 2) // leaver's but different project — untouched

	// Offboard the leaver so the owner-gone recovery path authorizes the transfer.
	require.NoError(t, c.storage.DeleteUser(ctx, 2))

	t.Run("reassigns only the leaver's secrets in the project", func(t *testing.T) {
		n, err := c.ReassignOwnedSecrets(ctx, p1.ID, 2, 3, 1)
		require.NoError(t, err)
		assert.Equal(t, 2, n)

		for _, id := range []uint{a, b} {
			s, _ := c.storage.GetSecret(ctx, id)
			assert.Equal(t, uint(3), s.OwnerID, "secret reassigned to heir")
		}
		ks, _ := c.storage.GetSecret(ctx, keep)
		assert.Equal(t, uint(1), ks.OwnerID, "admin's secret untouched")
		os, _ := c.storage.GetSecret(ctx, other)
		assert.Equal(t, uint(2), os.OwnerID, "other project's secret untouched")
	})

	t.Run("a second run is a no-op (nothing left owned by the leaver)", func(t *testing.T) {
		n, err := c.ReassignOwnedSecrets(ctx, p1.ID, 2, 3, 1)
		require.NoError(t, err)
		assert.Equal(t, 0, n)
	})

	t.Run("from == to is rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, p1.ID, 3, 3, 1)
		require.Error(t, err)
	})

	t.Run("a non-existent new owner is rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, p1.ID, 2, 999, 1)
		require.Error(t, err)
	})

	t.Run("zero IDs are rejected", func(t *testing.T) {
		_, err := c.ReassignOwnedSecrets(ctx, 0, 2, 3, 1)
		require.Error(t, err)
	})
}
