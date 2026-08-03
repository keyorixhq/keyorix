// core_s25_test.go — sprint-25 coverage blitz:
// rbac.go (AssignRoleToUser, RemoveRoleFromUser, ListUserRolesByEmail, ListUserPermissionsByEmail),
// rbac_management.go (ListPermissions, GetRoleWithPermissions, GetGroupRoleGrants,
// ListRolesWithPermissions, GetUserRoleAssignment),
// machine_identities.go (ListMachineIdentities),
// machine_token.go (ListMachineTokens, MachineTokenHashes, ListMachineRoles),
// membership_lifecycle.go (ListProjectMemberships),
// recertification.go (SetRecertificationCadence),
// rotation_executor.go (RotationBackendNames),
// rotation_policies.go (GetRotationPolicy, ListRotationPolicies),
// oidc.go (TrustsIssuer, OIDCEnabled, ListOIDCBindings, DeleteOIDCBinding),
// rate_limit.go (warnRateLimitUnsupportedOnce, IsPasswordResetRateLimited, RecordPasswordResetAttempt),
// webauthn.go (ListWebAuthnCredentials),
// invitations.go (ResendInvitationLink, StaleInvitations, RejectAccessRequest),
// scim.go (FindSCIMUser, ProvisionSCIMUser, ListSCIMUsers),
// sso.go (SetSSOProviders, SSOEnabled, SSOProviderNames, SSOCompleteURL, SAMLMetadata),
// permissions.go (EnforceSecretOwnerPermission),
// secret_listing_sharing.go (GetSecretSharingStatusWithIndicators),
// sod.go (requireMachineGrantNoSoDViolation),
// service.go (HasLicensedFeature, AuditLicenseState).
package core

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── rbac.go ──────────────────────────────────────────────────────────────────

func TestAssignRoleToUser_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignRoleToUser(context.Background(), "nobody@x.com", "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "User not found")
}

func TestAssignRoleToUser_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(&models.User{ID: 1, Email: "alice@x.com"}, nil)
	ms.On("GetRoleByName", mock.Anything, "ghost-role").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignRoleToUser(context.Background(), "alice@x.com", "ghost-role")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Role not found")
}

func TestRemoveRoleFromUser_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.RemoveRoleFromUser(context.Background(), "nobody@x.com", "admin")
	require.Error(t, err)
}

func TestRemoveRoleFromUser_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(&models.User{ID: 1}, nil)
	ms.On("GetRoleByName", mock.Anything, "ghost").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.RemoveRoleFromUser(context.Background(), "alice@x.com", "ghost")
	require.Error(t, err)
}

func TestListUserRolesByEmail_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.ListUserRolesByEmail(context.Background(), "nobody@x.com")
	require.Error(t, err)
}

func TestListUserRolesByEmail_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(&models.User{ID: 5}, nil)
	ms.On("GetUserRoles", mock.Anything, uint(5)).Return([]*models.Role{{ID: 1, Name: "editor"}}, nil)
	c := NewKeyorixCore(ms)
	roles, err := c.ListUserRolesByEmail(context.Background(), "alice@x.com")
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "editor", roles[0].Name)
}

func TestListUserPermissionsByEmail_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.ListUserPermissionsByEmail(context.Background(), "nobody@x.com")
	require.Error(t, err)
}

// ── rbac_management.go ────────────────────────────────────────────────────────

func TestListPermissions_ReturnsFromStorage(t *testing.T) {
	ms := new(MockStorage)
	// MockStorage.ListPermissions returns nil, nil by default — that's a success
	c := NewKeyorixCore(ms)
	perms, err := c.ListPermissions(context.Background())
	require.NoError(t, err)
	assert.Nil(t, perms)
}

func TestGetRoleWithPermissions_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, _, err := c.GetRoleWithPermissions(context.Background(), 99)
	require.Error(t, err)
}

func TestGetRoleWithPermissions_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetRole", mock.Anything, uint(1)).Return(&models.Role{ID: 1, Name: "admin"}, nil)
	// GetRolePermissions returns nil, nil from default MockStorage
	c := NewKeyorixCore(ms)
	role, perms, err := c.GetRoleWithPermissions(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, "admin", role.Name)
	assert.Nil(t, perms)
}

func TestGetGroupRoleGrants_ReturnsFromStorage(t *testing.T) {
	ms := new(MockStorage)
	// GetGroupRoleGrants returns nil, nil by default
	c := NewKeyorixCore(ms)
	grants, err := c.GetGroupRoleGrants(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, grants)
}

func TestListRolesWithPermissions_Empty(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRoles", mock.Anything).Return([]*models.Role{}, nil)
	c := NewKeyorixCore(ms)
	result, err := c.ListRolesWithPermissions(context.Background())
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestListRolesWithPermissions_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRoles", mock.Anything).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListRolesWithPermissions(context.Background())
	require.Error(t, err)
}

func TestListRolesWithPermissions_OneRole(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRoles", mock.Anything).Return([]*models.Role{{ID: 1, Name: "viewer"}}, nil)
	// GetRolePermissions returns nil, nil
	c := NewKeyorixCore(ms)
	result, err := c.ListRolesWithPermissions(context.Background())
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "viewer", result[0].Name)
}

func TestGetUserRoleAssignment_UserNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetUserRoleAssignment(context.Background(), 99)
	require.Error(t, err)
}

func TestGetUserRoleAssignment_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUser", mock.Anything, uint(1)).Return(&models.User{ID: 1, Username: "alice"}, nil)
	ms.On("GetUserRoles", mock.Anything, uint(1)).Return([]*models.Role{{ID: 2, Name: "editor"}}, nil)
	c := NewKeyorixCore(ms)
	asgn, err := c.GetUserRoleAssignment(context.Background(), 1)
	require.NoError(t, err)
	assert.Equal(t, uint(1), asgn.UserID)
	assert.Equal(t, "alice", asgn.Username)
	assert.Len(t, asgn.Roles, 1)
}

// ── machine_identities.go — ListMachineIdentities ─────────────────────────────

func TestListMachineIdentities_Error(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListMachineIdentities", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListMachineIdentities(context.Background(), 1)
	require.Error(t, err)
}

func TestListMachineIdentities_Success(t *testing.T) {
	ms := new(MockStorage)
	machines := []*models.MachineIdentity{{ID: 1, ProjectID: 1, Name: "ci-bot"}}
	ms.On("ListMachineIdentities", mock.Anything, uint(1)).Return(machines, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListMachineIdentities(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── machine_token.go — ListMachineTokens ─────────────────────────────────────

func TestListMachineTokens_MachineNotInProject(t *testing.T) {
	ms := new(MockStorage)
	// Machine belongs to project 2, caller says project 1
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ListMachineTokens(context.Background(), 1, 10)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListMachineTokens_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1}, nil)
	creds := []*models.MachineIdentityCredential{{ID: 1, MachineIdentityID: 10}}
	ms.On("ListMachineIdentityCredentials", mock.Anything, uint(10)).Return(creds, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListMachineTokens(context.Background(), 1, 10)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── machine_token.go — MachineTokenHashes ────────────────────────────────────

func TestMachineTokenHashes_Error(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListMachineIdentityCredentials", mock.Anything, uint(5)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.MachineTokenHashes(context.Background(), 5)
	require.Error(t, err)
}

func TestMachineTokenHashes_Success(t *testing.T) {
	ms := new(MockStorage)
	creds := []*models.MachineIdentityCredential{
		{ID: 1, TokenHash: "hash1"},
		{ID: 2, TokenHash: ""}, // empty hash is skipped
		{ID: 3, TokenHash: "hash3"},
	}
	ms.On("ListMachineIdentityCredentials", mock.Anything, uint(5)).Return(creds, nil)
	c := NewKeyorixCore(ms)
	hashes, err := c.MachineTokenHashes(context.Background(), 5)
	require.NoError(t, err)
	assert.Equal(t, []string{"hash1", "hash3"}, hashes)
}

// ── machine_token.go — ListMachineRoles ──────────────────────────────────────

func TestListMachineRoles_MachineNotInProject(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 99}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ListMachineRoles(context.Background(), 1, 10)
	require.Error(t, err)
}

func TestListMachineRoles_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1}, nil)
	ms.On("GetMachineRoles", mock.Anything, uint(10)).Return([]*models.Role{{ID: 2, Name: "secrets-reader"}}, nil)
	c := NewKeyorixCore(ms)
	roles, err := c.ListMachineRoles(context.Background(), 1, 10)
	require.NoError(t, err)
	require.Len(t, roles, 1)
	assert.Equal(t, "secrets-reader", roles[0].Name)
}

// ── membership_lifecycle.go — ListProjectMemberships ─────────────────────────

func TestListProjectMemberships_Error(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListProjectMemberships", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListProjectMemberships(context.Background(), 1)
	require.Error(t, err)
}

func TestListProjectMemberships_Success(t *testing.T) {
	ms := new(MockStorage)
	rows := []*models.ProjectMembership{{ID: 1, ProjectID: 1, UserID: 2}}
	ms.On("ListProjectMemberships", mock.Anything, uint(1)).Return(rows, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListProjectMemberships(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── recertification.go — SetRecertificationCadence ───────────────────────────

func TestSetRecertificationCadence_Zero(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetRecertificationCadence(0)
	// zero → default remains in effect
	assert.Equal(t, DefaultRecertificationCadenceDays, c.recertCadence())
}

func TestSetRecertificationCadence_Custom(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetRecertificationCadence(180)
	assert.Equal(t, 180, c.recertCadence())
}

// ── rotation_executor.go — RotationBackendNames ───────────────────────────────

func TestRotationBackendNames_NilManager(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// rotationManager is nil on a freshly constructed core
	names := c.RotationBackendNames()
	assert.Nil(t, names)
}

// ── rotation_policies.go — GetRotationPolicy, ListRotationPolicies ────────────

func TestGetRotationPolicy_Success(t *testing.T) {
	// GetRotationPolicy default mock returns &models.RotationPolicy{ID: id}
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	p, err := c.GetRotationPolicy(context.Background(), 3)
	require.NoError(t, err)
	assert.Equal(t, uint(3), p.ID)
}

func TestListRotationPolicies_Error(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListRotationPolicies(context.Background(), nil, nil)
	require.Error(t, err)
}

func TestListRotationPolicies_Success(t *testing.T) {
	ms := new(MockStorage)
	policies := []*models.RotationPolicy{{ID: 1, Name: "daily"}}
	ms.On("ListRotationPolicies", mock.Anything, (*uint)(nil), (*uint)(nil)).Return(policies, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListRotationPolicies(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// ── oidc.go — OIDCEnabled, TrustsIssuer, ListOIDCBindings, DeleteOIDCBinding ─

func TestOIDCEnabled_False(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	assert.False(t, c.OIDCEnabled())
}

func TestTrustsIssuer_TrueAndFalse(t *testing.T) {
	v := &OIDCVerifier{issuers: map[string]oidcIssuerTrust{
		"https://accounts.google.com": {},
	}}
	assert.True(t, v.TrustsIssuer("https://accounts.google.com"))
	assert.False(t, v.TrustsIssuer("https://evil.com"))
}

func TestListOIDCBindings_MachineNotInProject(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ListOIDCBindings(context.Background(), 1, 10)
	require.Error(t, err)
}

func TestListOIDCBindings_Success(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1}, nil)
	ms.On("ListOIDCBindings", mock.Anything, uint(10)).Return([]*models.MachineIdentityOIDCBinding{{ID: 1}}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListOIDCBindings(context.Background(), 1, 10)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestDeleteOIDCBinding_MachineNotInProject(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 2}, nil)
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 10, 1, 99)
	require.Error(t, err)
}

func TestDeleteOIDCBinding_BindingNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1}, nil)
	ms.On("GetOIDCBindingByID", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 10, 5, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding not found")
}

func TestDeleteOIDCBinding_WrongMachine(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(10)).Return(&models.MachineIdentity{ID: 10, ProjectID: 1}, nil)
	// Binding belongs to machine 999, not 10
	ms.On("GetOIDCBindingByID", mock.Anything, uint(5)).Return(&models.MachineIdentityOIDCBinding{ID: 5, MachineIdentityID: 999}, nil)
	c := NewKeyorixCore(ms)
	err := c.DeleteOIDCBinding(context.Background(), 1, 10, 5, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "binding not found")
}

// ── rate_limit.go — IsPasswordResetRateLimited, RecordPasswordResetAttempt ───

func TestIsPasswordResetRateLimited_EmptyIP(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// empty IP → never limited
	assert.False(t, c.IsPasswordResetRateLimited(context.Background(), ""))
}

func TestIsPasswordResetRateLimited_BelowThreshold(t *testing.T) {
	ms := new(MockStorage)
	// Returns 0 (below budget)
	ms.On("CountRecentLoginAttempts", mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil)
	c := NewKeyorixCore(ms)
	assert.False(t, c.IsPasswordResetRateLimited(context.Background(), "1.2.3.4"))
}

// Note: TestIsPasswordResetRateLimited_AtThreshold is intentionally omitted —
// the MockStorage.CountRecentLoginAttempts is a hardcoded stub (always returns 0, nil)
// that cannot be overridden via .On(). The at-threshold path is tested via real SQLite
// in rate_limit_test.go.

func TestRecordPasswordResetAttempt_EmptyIP(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// empty IP → no storage call
	c.RecordPasswordResetAttempt(context.Background(), "")
	ms.AssertNotCalled(t, "RecordLoginAttempt", mock.Anything, mock.Anything, mock.Anything)
}

// ── webauthn.go — ListWebAuthnCredentials ────────────────────────────────────

func TestListWebAuthnCredentials_ReturnsFromStorage(t *testing.T) {
	ms := new(MockStorage)
	// ListWebAuthnCredentials returns nil, nil by default
	c := NewKeyorixCore(ms)
	creds, err := c.ListWebAuthnCredentials(context.Background(), 1)
	require.NoError(t, err)
	assert.Nil(t, creds)
}

// ── invitations.go — ResendInvitationLink ────────────────────────────────────

func TestResendInvitationLink_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetProjectInvitation", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.ResendInvitationLink(context.Background(), 1, 99, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invitation not found")
}

func TestResendInvitationLink_WrongProject(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetProjectInvitation", mock.Anything, uint(5)).Return(&models.ProjectInvitation{ID: 5, ProjectID: 2, State: InvitationPending}, nil)
	c := NewKeyorixCore(ms)
	// caller is authorized for project 1, but invitation is in project 2
	_, err := c.ResendInvitationLink(context.Background(), 1, 5, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invitation not found")
}

func TestResendInvitationLink_NotPending(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetProjectInvitation", mock.Anything, uint(5)).Return(&models.ProjectInvitation{ID: 5, ProjectID: 1, State: InvitationAccepted}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.ResendInvitationLink(context.Background(), 1, 5, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending invitation")
}

// ── invitations.go — StaleInvitations ────────────────────────────────────────

func TestStaleInvitations_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListProjectInvitations", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.StaleInvitations(context.Background(), 1, 7*24*time.Hour)
	require.Error(t, err)
}

func TestStaleInvitations_None(t *testing.T) {
	ms := new(MockStorage)
	// All invitations are recent or accepted
	recent := time.Now()
	ms.On("ListProjectInvitations", mock.Anything, uint(1)).Return([]*models.ProjectInvitation{
		{ID: 1, State: InvitationAccepted, CreatedAt: recent},
		{ID: 2, State: InvitationPending, CreatedAt: recent},
	}, nil)
	c := NewKeyorixCore(ms)
	stale, err := c.StaleInvitations(context.Background(), 1, 24*time.Hour)
	require.NoError(t, err)
	assert.Empty(t, stale)
}

func TestStaleInvitations_SomeStale(t *testing.T) {
	ms := new(MockStorage)
	old := time.Now().Add(-30 * 24 * time.Hour)
	recent := time.Now()
	ms.On("ListProjectInvitations", mock.Anything, uint(1)).Return([]*models.ProjectInvitation{
		{ID: 1, State: InvitationPending, CreatedAt: old},
		{ID: 2, State: InvitationPending, CreatedAt: recent},
	}, nil)
	c := NewKeyorixCore(ms)
	stale, err := c.StaleInvitations(context.Background(), 1, 7*24*time.Hour)
	require.NoError(t, err)
	require.Len(t, stale, 1)
	assert.Equal(t, uint(1), stale[0].ID)
}

// ── invitations.go — RejectAccessRequest ─────────────────────────────────────

func TestRejectAccessRequest_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAccessRequest", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.RejectAccessRequest(context.Background(), 1, 99, 1, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access request not found")
}

func TestRejectAccessRequest_WrongProject(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAccessRequest", mock.Anything, uint(5)).Return(&models.AccessRequest{ID: 5, ProjectID: 2, State: AccessRequestPending}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.RejectAccessRequest(context.Background(), 1, 5, 1, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access request not found")
}

func TestRejectAccessRequest_NotPending(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAccessRequest", mock.Anything, uint(5)).Return(&models.AccessRequest{ID: 5, ProjectID: 1, State: AccessRequestApproved}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.RejectAccessRequest(context.Background(), 1, 5, 1, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending request")
}

func TestRejectAccessRequest_Success(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 5, ProjectID: 1, UserID: 2, State: AccessRequestPending}
	ms.On("GetAccessRequest", mock.Anything, uint(5)).Return(req, nil)
	ms.On("UpdateAccessRequest", mock.Anything, mock.Anything).Return(true, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	// notifyAccessResolved tries to get the requester for notification
	ms.On("GetUser", mock.Anything, uint(2)).Return(&models.User{ID: 2, Email: "u@x.com"}, nil)
	ms.On("ListNotifications", mock.Anything, uint(2), mock.Anything, mock.Anything).Return([]*models.Notification{}, nil)
	ms.On("CreateNotification", mock.Anything, mock.Anything).Return(&models.Notification{}, nil)
	c := NewKeyorixCore(ms)
	got, err := c.RejectAccessRequest(context.Background(), 1, 5, 1, "not now")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestRejected, got.State)
}

func TestRejectAccessRequest_ConcurrentUpdate(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 5, ProjectID: 1, UserID: 2, State: AccessRequestPending}
	ms.On("GetAccessRequest", mock.Anything, uint(5)).Return(req, nil)
	// ok=false: concurrent resolution
	ms.On("UpdateAccessRequest", mock.Anything, mock.Anything).Return(false, nil)
	c := NewKeyorixCore(ms)
	_, err := c.RejectAccessRequest(context.Background(), 1, 5, 1, "no")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "concurrently")
}

// ── scim.go — FindSCIMUser ────────────────────────────────────────────────────

func TestFindSCIMUser_BothEmpty(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	u, err := c.FindSCIMUser(context.Background(), "", "")
	require.NoError(t, err)
	assert.Nil(t, u)
}

func TestFindSCIMUser_FoundByExternalID(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext123").Return(&models.User{ID: 1, ExternalID: "ext123"}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.FindSCIMUser(context.Background(), "ext123", "")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, uint(1), u.ID)
}

func TestFindSCIMUser_FoundByEmail(t *testing.T) {
	ms := new(MockStorage)
	// ExternalID miss
	ms.On("GetUserByExternalID", mock.Anything, "ext999").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(&models.User{ID: 2}, nil)
	c := NewKeyorixCore(ms)
	u, err := c.FindSCIMUser(context.Background(), "ext999", "alice@x.com")
	require.NoError(t, err)
	require.NotNil(t, u)
	assert.Equal(t, uint(2), u.ID)
}

func TestFindSCIMUser_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext999").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, storage.ErrUserNotFound)
	c := NewKeyorixCore(ms)
	u, err := c.FindSCIMUser(context.Background(), "ext999", "nobody@x.com")
	require.NoError(t, err)
	assert.Nil(t, u)
}

// ── scim.go — ListSCIMUsers ───────────────────────────────────────────────────

func TestListSCIMUsers_StorageError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListUsers", mock.Anything, mock.Anything).Return(nil, int64(0), errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.ListSCIMUsers(context.Background())
	require.Error(t, err)
}

func TestListSCIMUsers_Empty(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListUsers", mock.Anything, mock.Anything).Return([]*models.User{}, int64(0), nil)
	c := NewKeyorixCore(ms)
	users, err := c.ListSCIMUsers(context.Background())
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestListSCIMUsers_OnePage(t *testing.T) {
	ms := new(MockStorage)
	users := []*models.User{{ID: 1}, {ID: 2}}
	ms.On("ListUsers", mock.Anything, mock.Anything).Return(users, int64(2), nil)
	c := NewKeyorixCore(ms)
	got, err := c.ListSCIMUsers(context.Background())
	require.NoError(t, err)
	assert.Len(t, got, 2)
}

// ── sso.go — SetSSOProviders, SSOEnabled, SSOProviderNames, SSOCompleteURL ───

func TestSSOEnabled_False(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	assert.False(t, c.SSOEnabled())
}

func TestSSOEnabled_True(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetSSOProviders(map[string]*SSOProvider{"google": {Name: "google"}}, nil)
	assert.True(t, c.SSOEnabled())
}

func TestSSOProviderNames_Sorted(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetSSOProviders(map[string]*SSOProvider{
		"zz": {Name: "zz"},
		"aa": {Name: "aa"},
		"mm": {Name: "mm"},
	}, nil)
	names := c.SSOProviderNames()
	assert.Equal(t, []string{"aa", "mm", "zz"}, names)
}

func TestSSOCompleteURL_Found(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetSSOProviders(map[string]*SSOProvider{
		"google": {Name: "google", CompleteURL: "https://app/callback"},
	}, nil)
	url, ok := c.SSOCompleteURL("google")
	assert.True(t, ok)
	assert.Equal(t, "https://app/callback", url)
}

func TestSSOCompleteURL_NotFound(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetSSOProviders(map[string]*SSOProvider{}, nil)
	_, ok := c.SSOCompleteURL("nonexistent")
	assert.False(t, ok)
}

// ── secret_listing_sharing.go — GetSecretSharingStatusWithIndicators ──────────

func TestGetSecretSharingStatusWithIndicators_ZeroSecretID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 0, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret ID is required")
}

func TestGetSecretSharingStatusWithIndicators_ZeroUserID(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 1, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestGetSecretSharingStatusWithIndicators_SecretNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 5, 1)
	require.Error(t, err)
}

func TestGetSecretSharingStatusWithIndicators_SharesError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 10}, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return(nil, errors.New("db err"))
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 1, 10)
	require.Error(t, err)
}

func TestGetSecretSharingStatusWithIndicators_OwnerNoShares(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 7}, nil)
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	c := NewKeyorixCore(ms)
	status, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 1, 7)
	require.NoError(t, err)
	assert.True(t, status.IsOwner)
	assert.False(t, status.IsShared)
}

func TestGetSecretSharingStatusWithIndicators_NonOwnerWithShare(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 99}, nil)
	share := &models.ShareRecord{
		ID: 1, SecretID: 1, RecipientID: 7, IsGroup: false, Permission: "read",
	}
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{share}, nil)
	ms.On("GetUser", mock.Anything, uint(7)).Return(&models.User{ID: 7, Username: "bob"}, nil)
	c := NewKeyorixCore(ms)
	status, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 1, 7)
	require.NoError(t, err)
	assert.False(t, status.IsOwner)
	assert.Equal(t, "read", status.UserPermission)
}

func TestGetSecretSharingStatusWithIndicators_NonOwnerNoShare(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSecret", mock.Anything, uint(1)).Return(&models.SecretNode{ID: 1, OwnerID: 99}, nil)
	// no shares
	ms.On("ListSharesBySecret", mock.Anything, uint(1)).Return([]*models.ShareRecord{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.GetSecretSharingStatusWithIndicators(context.Background(), 1, 42)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission")
}

// ── permissions.go — EnforceSecretOwnerPermission ─────────────────────────────

func TestEnforceSecretOwnerPermission_NotOwner(t *testing.T) {
	ms := new(MockStorage)
	// Secret owned by user 99, caller is user 1
	ms.On("GetSecret", mock.Anything, uint(5)).Return(&models.SecretNode{ID: 5, OwnerID: 99}, nil)
	// ListSharesBySecret returns no shares
	ms.On("ListSharesBySecret", mock.Anything, uint(5)).Return([]*models.ShareRecord{}, nil)
	ms.On("GetUserGroups", mock.Anything, uint(1)).Return([]*models.Group{}, nil)
	// RBAC fallback (r124): no roles → deny.
	ms.On("GetUserRoleIDsAt", mock.Anything, uint(1), mock.Anything).Return([]uint{}, nil)
	ms.On("GetUserGroupRoleIDsAt", mock.Anything, uint(1), mock.Anything).Return([]uint{}, nil)
	c := NewKeyorixCore(ms)
	_, err := c.EnforceSecretOwnerPermission(context.Background(), 5, 1)
	require.Error(t, err)
}

// ── service.go — HasLicensedFeature, AuditLicenseState (with nil gate) ────────

func TestHasLicensedFeature_NilGate(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	// nil gate → HasFeature returns false
	result := c.HasLicensedFeature("airgap_updates")
	assert.False(t, result)
}

func TestAuditLicenseState_NilGate(t *testing.T) {
	ms := new(MockStorage)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	// Should not panic even with nil gate
	require.NotPanics(t, func() {
		c.AuditLicenseState(context.Background())
	})
}

// ── sod.go — requireMachineGrantNoSoDViolation ────────────────────────────────

func TestRequireMachineGrantNoSoDViolation_NoMachine(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(0)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	// Zero machineID → GetMachineIdentity fails or returns nil machine → requires no SoD roles
	// ListSoDPolicies returns nil by default
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 0, 1)
	// No SoD policies → no violation
	require.NoError(t, err)
}
