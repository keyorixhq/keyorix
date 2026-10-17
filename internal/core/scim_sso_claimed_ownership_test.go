package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// #3418: a native account that signs in through SSO by verified email is claimed
// with external_id = "sso:<provider>:<sub>" (resolveSSOUser). scimManaged used to be
// ExternalID != "", so from that login on a SCIM token holder could read, edit,
// deactivate and delete the native account and add it to groups. These drive the
// real claim, then every SCIM entry point, and require the same refusal a native
// account with no external id gets.
func TestSCIM_SSOClaimedNativeAccountIsNotSCIMManaged(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "nativeuser", UsernameFolded: "nativeuser",
		Email: "native@x.io", EmailFolded: "native@x.io", IsActive: true, AccountState: AccountActive}).Error)

	claimed, err := c.resolveSSOUser(ctx, "okta", "sub-native", "native@x.io", true)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	require.Equal(t, ssoExternalID("okta", "sub-native"), claimed.ExternalID,
		"precondition: the SSO email fallback claimed the native account")

	_, err = c.GetSCIMUser(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account", "GET must refuse an SSO-claimed native account")

	newEmail := "attacker@x.io"
	_, err = c.UpdateSCIMUser(ctx, 9, 1, nil, &newEmail, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account", "PUT/PATCH must refuse an SSO-claimed native account")

	no := false
	_, err = c.UpdateSCIMUser(ctx, 9, 1, nil, nil, &no)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account", "active=false must refuse an SSO-claimed native account")

	err = c.DeprovisionSCIMUser(ctx, 9, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account", "DELETE must refuse an SSO-claimed native account")

	page, total, err := c.ListSCIMUsersPage(ctx, 1, 10)
	require.NoError(t, err)
	assert.Zero(t, total, "the SCIM list must not count an SSO-claimed native account")
	assert.Empty(t, page)

	_, err = c.ProvisionSCIMGroup(ctx, 9, "eng", []uint{1})
	require.Error(t, err, "SCIM must not add an SSO-claimed native account to a group")

	var got models.User
	require.NoError(t, db.First(&got, 1).Error)
	assert.Equal(t, "native@x.io", got.Email)
	assert.True(t, got.IsActive)
	assert.Equal(t, AccountActive, got.AccountState)
}

// TestSCIM_SSOJITAccountIsNotSCIMManaged: an account SSO JIT-provisioned carries
// the same "sso:" id, and the row cannot tell it from a claimed native account, so
// it is outside SCIM's scope too (the rule stated in the #3418 PR).
func TestSCIM_SSOJITAccountIsNotSCIMManaged(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.User{ID: 1, Username: "jituser", Email: "jit@x.io", EmailFolded: "jit@x.io",
		IsActive: true, AccountState: AccountActive, ExternalID: ssoExternalID("okta", "sub-jit")}).Error)

	_, err := c.GetSCIMUser(ctx, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a SCIM-managed account")
}

// TestSCIM_SCIMCreatedThenSSOLinkedStaysManaged: the legitimate integration. A
// SCIM-created account carries the IdP's externalId; an SSO login by verified
// email resolves to it without rewriting that id, so SCIM keeps managing it.
func TestSCIM_SCIMCreatedThenSSOLinkedStaysManaged(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)
	created, err := c.ProvisionSCIMUser(ctx, 0, "dana@x.io", "Dana", "dana@x.io", "00u-dana", true)
	require.NoError(t, err)

	linked, err := c.resolveSSOUser(ctx, "okta", "sub-dana", "dana@x.io", true)
	require.NoError(t, err)
	require.NotNil(t, linked)
	require.Equal(t, created.ID, linked.ID)
	require.Equal(t, "00u-dana", linked.ExternalID, "an SSO link must not rewrite a SCIM externalId")

	_, err = c.GetSCIMUser(ctx, created.ID)
	require.NoError(t, err)
	no := false
	_, err = c.UpdateSCIMUser(ctx, 9, created.ID, nil, nil, &no)
	require.NoError(t, err)
}

// TestProvisionSCIMUser_RefusesSSONamespaceExternalID: the "sso:" namespace is
// reserved for SSO-bound identities. A SCIM create may not mint an account inside
// it: the account would be unmanageable by SCIM afterwards, and an id such as
// "sso:okta:<sub>" would pre-bind that SSO subject to an account SCIM chose.
func TestProvisionSCIMUser_RefusesSSONamespaceExternalID(t *testing.T) {
	t.Parallel()
	c, db := newSCIMGuardCore(t)
	ctx := context.Background()
	require.NoError(t, db.Create(&models.Role{Name: "system_viewer"}).Error)

	_, err := c.ProvisionSCIMUser(ctx, 0, "eve@x.io", "Eve", "eve@x.io", ssoExternalID("okta", "sub-eve"), true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "externalId")
	var n int64
	require.NoError(t, db.Model(&models.User{}).Count(&n).Error)
	assert.Zero(t, n, "no account may be created")
}
