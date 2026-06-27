package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newSCIMGuardCore(t *testing.T) (*KeyorixCore, *gorm.DB) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.User{}, &models.Role{}, &models.Permission{}, &models.RolePermission{},
		&models.UserRole{}, &models.Group{}, &models.UserGroup{}, &models.GroupRole{},
		&models.Session{}, &models.AuditEvent{},
	))
	return NewKeyorixCore(store.NewLocalStorage(db)), db
}

func TestUpdateSCIMUser_RejectsEmailCollision(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "admin", Email: "admin@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", Email: "bob@x.io", IsActive: true, AccountState: AccountActive}).Error)

	adminEmail := "admin@x.io"
	_, err := c.UpdateSCIMUser(ctx, 9, 2, nil, &adminEmail, nil)
	require.Error(t, err, "SCIM must not overwrite user 2's email to collide with the admin's")
	assert.Contains(t, err.Error(), "already in use")
}

func TestUpdateSCIMUser_RefusesLastAdminDeactivation(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error) // global admin

	no := false
	_, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "last install administrator")
}

func TestUpdateSCIMUser_AllowsAdminDeactivationWhenAnotherExists(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "root2", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)

	no := false
	off, err := c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.NoError(t, err, "deactivating one of two admins is allowed")
	assert.False(t, off.IsActive)
}

func TestPatchSCIMGroup_RefusesAddingMemberToAdminGroup(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{2}, nil)
	require.Error(t, err, "SCIM must not add a member to an admin-bearing group")
	assert.Contains(t, err.Error(), "administrative roles")
}
