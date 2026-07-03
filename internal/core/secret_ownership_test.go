package core

import (
	"context"
	"errors"
	"testing"
	"time"

	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// transientOwnerLookup wraps LocalStorage so GetUser(failID) returns a transient
// (non-not-found) error, simulating a momentary backend failure during the owner
// lookup. All other methods/users behave normally.
type transientOwnerLookup struct {
	*store.LocalStorage
	failID uint
}

func (t *transientOwnerLookup) GetUser(ctx context.Context, id uint) (*models.User, error) {
	if id == t.failID {
		return nil, errors.New("db timeout") // transient, NOT storage.ErrUserNotFound
	}
	return t.LocalStorage.GetUser(ctx, id)
}

// newOwnershipFixture builds an in-memory core with users 1 (owner), 2, 3 and a
// secret owned by user 1.
func newOwnershipFixture(t *testing.T) (*KeyorixCore, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.User{},
		&models.Role{}, &models.Permission{}, &models.RolePermission{}, &models.UserRole{},
		&models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Project{}, &models.Environment{}))
	for _, u := range []models.User{
		{ID: 1, Username: "owner", Email: "o@test.com"},
		{ID: 2, Username: "alice", Email: "a@test.com"},
		{ID: 3, Username: "bob", Email: "b@test.com"},
		{ID: 4, Username: "carol", Email: "c@test.com"}, // no role — a transfer target with no project access
	} {
		require.NoError(t, db.Create(&u).Error)
	}
	// A reader role with secrets.read, granted to users 2 and 3 in project 1 (the
	// secret's scope) so they're eligible to become the owner; user 4 holds nothing.
	require.NoError(t, db.Create(&models.Role{ID: 1, Name: "reader"}).Error)
	require.NoError(t, db.Create(&models.Permission{ID: 1, Name: "secrets.read", Resource: "secrets", Action: "read"}).Error)
	require.NoError(t, db.Create(&models.RolePermission{RoleID: 1, PermissionID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 1, ProjectID: 1}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 1, ProjectID: 1}).Error)
	st := store.NewLocalStorage(db)
	c := &KeyorixCore{storage: st, now: time.Now}
	secret, err := st.CreateSecret(context.Background(), &models.SecretNode{
		Name: "db", ProjectID: 1, EnvironmentID: 1, Type: "password", OwnerID: 1, IsSecret: true,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.NoError(t, err)
	return c, secret.ID
}

func TestTransferSecretOwnership(t *testing.T) {
	ctx := context.Background()

	t.Run("owner transfers to another user", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		updated, err := c.TransferSecretOwnership(ctx, id, 2, 1)
		require.NoError(t, err)
		assert.EqualValues(t, 2, updated.OwnerID)
		// The new owner now has owner permission; the old owner does not.
		_, err = c.CheckSecretPermission(ctx, id, 2, PermissionOwner)
		require.NoError(t, err)
		_, err = c.CheckSecretPermission(ctx, id, 1, PermissionOwner)
		require.Error(t, err)
	})

	t.Run("non-owner cannot transfer an actively-owned secret", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 3, 2) // actor 2 is not the owner
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only the current owner")
	})

	t.Run("recovery: a departed owner's secret can be transferred by anyone authorized", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// Simulate the owner (user 1) leaving: delete the account.
		require.NoError(t, c.storage.DeleteUser(ctx, 1))
		updated, err := c.TransferSecretOwnership(ctx, id, 2, 3) // actor 3, owner gone
		require.NoError(t, err)
		assert.EqualValues(t, 2, updated.OwnerID)
	})

	t.Run("rejects a new owner with no access to the secret's scope", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// User 4 holds no role in project 1, so it must not be handed ownership.
		_, err := c.TransferSecretOwnership(ctx, id, 4, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no access")
	})

	t.Run("rejects a non-existent new owner", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 999, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "new owner")
	})

	t.Run("rejects transferring to the current owner", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 1, 1)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already owned")
	})

	t.Run("fail-closed: a transient owner-lookup error does NOT permit takeover", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		// Wrap storage so the OWNER lookup (user 1) fails transiently (not not-found),
		// while other users resolve normally.
		base := c.storage.(*store.LocalStorage)
		c.storage = &transientOwnerLookup{LocalStorage: base, failID: 1}
		_, err := c.TransferSecretOwnership(ctx, id, 2, 3) // non-owner actor, owner "errors"
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only the current owner",
			"a transient lookup error must be treated as owner-present (fail closed)")
	})

	t.Run("GetUser surfaces the typed not-found sentinel", func(t *testing.T) {
		c, _ := newOwnershipFixture(t)
		_, err := c.storage.GetUser(ctx, 999)
		require.Error(t, err)
		assert.ErrorIs(t, err, coreStorage.ErrUserNotFound)
	})

	t.Run("validates ids", func(t *testing.T) {
		c, id := newOwnershipFixture(t)
		_, err := c.TransferSecretOwnership(ctx, id, 0, 1)
		require.Error(t, err)
		_, err = c.TransferSecretOwnership(ctx, 0, 2, 1)
		require.Error(t, err)
	})
}
