package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestListAdminsWithoutMFA_ReturnsOnlyAdminHoldersMissingBothFactors(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.Role{ID: 11, Name: "viewer"}).Error)

	require.NoError(t, db.Create(&models.User{ID: 1, Username: "no-mfa-admin", Email: "nomfa@x.io", IsActive: true, AccountState: AccountActive}).Error)
	require.NoError(t, db.Create(&models.User{ID: 2, Username: "totp-admin", Email: "totp@x.io", IsActive: true, AccountState: AccountActive, MFAEnabled: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 3, Username: "passkey-admin", Email: "passkey@x.io", IsActive: true, AccountState: AccountActive, WebAuthnEnabled: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 4, Username: "no-mfa-viewer", Email: "viewer@x.io", IsActive: true, AccountState: AccountActive}).Error)

	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 2, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 3, RoleID: 10}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 4, RoleID: 11}).Error)

	admins, err := c.ListAdminsWithoutMFA(ctx)
	require.NoError(t, err)
	require.Len(t, admins, 1, "only the admin-tier holder with neither TOTP nor WebAuthn should be reported")
	assert.Equal(t, "no-mfa-admin", admins[0].Username)
}

func TestListAdminsWithoutMFA_NoAdminRoleSeeded_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "lonely", Email: "lonely@x.io", IsActive: true, AccountState: AccountActive}).Error)

	admins, err := c.ListAdminsWithoutMFA(ctx)
	require.NoError(t, err)
	assert.Empty(t, admins, "no install-admin role exists to seed adminIDs, so there is nothing to report")
}

func TestListAdminsWithoutMFA_AllAdminsCompliant_ReturnsEmpty(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()

	require.NoError(t, db.Create(&models.Role{ID: 10, Name: "super_admin", BypassesPermissionChecks: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "root", Email: "root@x.io", IsActive: true, AccountState: AccountActive, MFAEnabled: true}).Error)
	require.NoError(t, db.Create(&models.UserRole{UserID: 1, RoleID: 10}).Error)

	admins, err := c.ListAdminsWithoutMFA(ctx)
	require.NoError(t, err)
	assert.Empty(t, admins)
}
