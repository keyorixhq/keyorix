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
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "bob", IsActive: true, AccountState: AccountActive, ExternalID: "okta|bob"}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Keyorix-Admins"}).Error)
	require.NoError(t, db.Create(&models.GroupRole{GroupID: 5, RoleID: 10}).Error) // group confers admin

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{2}, nil)
	require.Error(t, err, "SCIM must not add a member to an admin-bearing group")
	assert.Contains(t, err.Error(), "administrative roles")
}

// --- #167: SCIM group membership mutations must refuse non-SCIM-managed targets ---
//
// None of ProvisionSCIMGroup/ReplaceSCIMGroup/PatchSCIMGroup checked the target
// member's ExternalID before AddUserToGroup, so a valid SCIM group-provisioning
// token could add ANY native user — including one the attacker already controls —
// into a group. If that group carries an admin-conferring role, membership alone
// grants the role immediately. Each function below is exercised with both a
// SCIM-managed target (positive control — must succeed) and a non-SCIM-managed
// native target (negative control — must be refused, and membership must not
// take effect).

func TestProvisionSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)

	group, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1})
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestProvisionSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	// Native user: no ExternalID — never SCIM-provisioned.
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)

	group, err := c.ProvisionSCIMGroup(ctx, 9, "Engineering", []uint{1})
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user at group creation")
	assert.Contains(t, err.Error(), "SCIM-managed")
	assert.Nil(t, group)

	// No group should have been left dangling with the rejected membership.
	var count int64
	require.NoError(t, db.Model(&models.Group{}).Where("name = ?", "Engineering").Count(&count).Error)
	assert.Zero(t, count, "the group must not be created when the member set is refused")
}

func TestReplaceSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.ReplaceSCIMGroup(ctx, 9, 5, "", []uint{1})
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestReplaceSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.ReplaceSCIMGroup(ctx, 9, 5, "", []uint{1})
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user via PUT")
	assert.Contains(t, err.Error(), "SCIM-managed")

	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	assert.Empty(t, members, "the refused member must not have been added")
}

func TestPatchSCIMGroup_AllowsSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "alice", IsActive: true, AccountState: AccountActive, ExternalID: "okta|alice"}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{1}, nil)
	require.NoError(t, err)
	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, uint(1), members[0].ID)
}

func TestPatchSCIMGroup_RefusesNonSCIMManagedMember(t *testing.T) {
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "native", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.Group{ID: 5, Name: "Engineering"}).Error)

	_, err := c.PatchSCIMGroup(ctx, 9, 5, nil, []uint{1}, nil)
	require.Error(t, err, "SCIM must not add a non-SCIM-managed native user via PATCH")
	assert.Contains(t, err.Error(), "SCIM-managed")

	members, err := c.storage.ListGroupMembers(ctx, 5)
	require.NoError(t, err)
	assert.Empty(t, members, "the refused member must not have been added")
}
