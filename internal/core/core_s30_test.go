// core_s30_test.go — sprint-30 coverage blitz:
// scim.go (ProvisionSCIMUser success path, email fallback, FindSCIMUser),
// machine_token.go (AssignMachineRole success/failure paths),
// invitations.go (WithdrawAccessRequest paths),
// sod.go (requireMachineGrantNoSoDViolation),
// auth.go (Login MFA path, Login success),
// access_review_campaign.go (OpenAccessReviewCampaign storage success, CloseAccessReviewCampaign).
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// ── scim.go — FindSCIMUser ────────────────────────────────────────────────

func TestFindSCIMUser_ByExternalID(t *testing.T) {
	ms := new(MockStorage)
	u := &models.User{ID: 1, ExternalID: "ext-123"}
	ms.On("GetUserByExternalID", mock.Anything, "ext-123").Return(u, nil)
	c := NewKeyorixCore(ms)
	result, err := c.FindSCIMUser(context.Background(), "ext-123", "")
	require.NoError(t, err)
	assert.Equal(t, uint(1), result.ID)
}

func TestFindSCIMUser_ByEmail(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "alice@x.com").Return(&models.User{ID: 2}, nil)
	c := NewKeyorixCore(ms)
	result, err := c.FindSCIMUser(context.Background(), "", "alice@x.com")
	require.NoError(t, err)
	assert.Equal(t, uint(2), result.ID)
}

func TestFindSCIMUser_NotFound_s30(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-999").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "nobody@x.com").Return(nil, storage.ErrUserNotFound)
	c := NewKeyorixCore(ms)
	result, err := c.FindSCIMUser(context.Background(), "ext-999", "nobody@x.com")
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestFindSCIMUser_ExternalIDLookupError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-1").Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.FindSCIMUser(context.Background(), "ext-1", "")
	require.Error(t, err)
}

func TestFindSCIMUser_EmailLookupError(t *testing.T) {
	ms := new(MockStorage)
	// externalID empty → skip that check. Email check fails.
	ms.On("GetUserByEmail", mock.Anything, "err@x.com").Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.FindSCIMUser(context.Background(), "", "err@x.com")
	require.Error(t, err)
}

// ── scim.go — ProvisionSCIMUser success path ─────────────────────────────

func TestProvisionSCIMUser_Success(t *testing.T) {
	ms := new(MockStorage)
	// FindSCIMUser → GetUserByExternalID not found, GetUserByEmail not found.
	ms.On("GetUserByExternalID", mock.Anything, "ext-new").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "bob@x.com").Return(nil, storage.ErrUserNotFound)
	// deriveSCIMUsername → GetUserByUsername("bob") not found → "bob" is available.
	ms.On("GetUserByUsername", mock.Anything, "bob").Return(nil, storage.ErrUserNotFound)
	// CreateUser.
	created := &models.User{ID: 10, Username: "bob", Email: "bob@x.com", AccountState: "pending_first_login"}
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(created, nil)
	// Best-effort role assignment (system_viewer) — GetRoleByName returns not found → skipped.
	ms.On("GetRoleByName", mock.Anything, "system_viewer").Return(nil, errors.New("not found"))
	// LogAuditEvent for writeAuditEvent.
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	u, err := c.ProvisionSCIMUser(context.Background(), 0, "bob@x.com", "", "", "ext-new", true)
	require.NoError(t, err)
	assert.Equal(t, uint(10), u.ID)
}

// ADR-022's domain allowlist previously only gated the email-based
// InviteToProject/InviteGlobal flow — a SCIM directory sync from an
// unapproved domain (e.g. a misconfigured/multi-tenant IdP) could still
// silently mint an account. Verify it's now enforced here too.
func TestProvisionSCIMUser_RejectsDisallowedDomain(t *testing.T) {
	ms := new(MockStorage)
	c := NewKeyorixCore(ms)
	c.SetMembershipDomainAllowlist([]string{"allowed.com"})

	_, err := c.ProvisionSCIMUser(context.Background(), 0, "eve@evil.com", "", "", "ext-eve", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")
	ms.AssertNotCalled(t, "CreateUser", mock.Anything, mock.Anything)
}

func TestProvisionSCIMUser_EmailFallback(t *testing.T) {
	// When email is empty, it defaults to userName.
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-2").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "charlie@x.com").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByUsername", mock.Anything, "charlie").Return(nil, storage.ErrUserNotFound)
	created := &models.User{ID: 11, Username: "charlie", Email: "charlie@x.com"}
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(created, nil)
	ms.On("GetRoleByName", mock.Anything, "system_viewer").Return(nil, errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	u, err := c.ProvisionSCIMUser(context.Background(), 0, "charlie@x.com", "", "", "ext-2", true)
	require.NoError(t, err)
	assert.Equal(t, uint(11), u.ID)
}

func TestProvisionSCIMUser_Inactive(t *testing.T) {
	// active=false → AccountDeprovisioned state.
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-3").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "dave@x.com").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByUsername", mock.Anything, "dave").Return(nil, storage.ErrUserNotFound)
	created := &models.User{ID: 12, Username: "dave", Email: "dave@x.com", AccountState: "deprovisioned"}
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(created, nil)
	ms.On("GetRoleByName", mock.Anything, "system_viewer").Return(nil, errors.New("not found"))
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	u, err := c.ProvisionSCIMUser(context.Background(), 0, "dave@x.com", "", "dave@x.com", "ext-3", false)
	require.NoError(t, err)
	assert.Equal(t, uint(12), u.ID)
}

func TestProvisionSCIMUser_CreateUserDuplicateEmail(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-4").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "dup@x.com").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByUsername", mock.Anything, "dup").Return(nil, storage.ErrUserNotFound)
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, storage.ErrDuplicateEmail)
	c := NewKeyorixCore(ms)
	_, err := c.ProvisionSCIMUser(context.Background(), 0, "dup@x.com", "", "dup@x.com", "ext-4", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestProvisionSCIMUser_CreateUserError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetUserByExternalID", mock.Anything, "ext-5").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByEmail", mock.Anything, "err2@x.com").Return(nil, storage.ErrUserNotFound)
	ms.On("GetUserByUsername", mock.Anything, "err2").Return(nil, storage.ErrUserNotFound)
	ms.On("CreateUser", mock.Anything, mock.AnythingOfType("*models.User")).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	_, err := c.ProvisionSCIMUser(context.Background(), 0, "err2@x.com", "", "err2@x.com", "ext-5", true)
	require.Error(t, err)
}

// ── machine_token.go — AssignMachineRole ─────────────────────────────────

func TestAssignMachineRole_MachineNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignMachineRole(context.Background(), 1, 2, Scope{ProjectID: 5}, 1, false)
	require.Error(t, err)
}

func TestAssignMachineRole_RoleNotFound(t *testing.T) {
	ms := new(MockStorage)
	machine := &models.MachineIdentity{ID: 1, ProjectID: 5}
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(machine, nil)
	ms.On("GetRole", mock.Anything, uint(2)).Return(nil, errors.New("role not found"))
	c := NewKeyorixCore(ms)
	err := c.AssignMachineRole(context.Background(), 1, 2, Scope{ProjectID: 5}, 1, false)
	require.Error(t, err)
}

func TestAssignMachineRole_Success(t *testing.T) {
	ms := new(MockStorage)
	machine := &models.MachineIdentity{ID: 1, ProjectID: 5, Name: "ci-runner", State: MachineActive}
	role := &models.Role{ID: 2, Name: "viewer"} // non-admin role → requireAuthorityForRole returns nil
	ms.On("GetMachineIdentity", mock.Anything, uint(1)).Return(machine, nil)
	ms.On("GetRole", mock.Anything, uint(2)).Return(role, nil)
	// ListSoDPolicies: smart stub returns nil if not mocked.
	// AssignMachineRole.
	ms.On("AssignMachineRole", mock.Anything, uint(1), uint(2), mock.AnythingOfType("storage.Scope")).Return(nil)
	// LogAuditEvent for logMachineEvent → writeAuditEventFull.
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.AssignMachineRole(context.Background(), 1, 2, Scope{ProjectID: 5}, 1, false)
	require.NoError(t, err)
}

// ── invitations.go — WithdrawAccessRequest ───────────────────────────────

func TestWithdrawAccessRequest_NotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAccessRequest", mock.Anything, uint(99)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 99, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "access request not found")
}

func TestWithdrawAccessRequest_WrongUser(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 1, UserID: 5, State: AccessRequestPending}
	ms.On("GetAccessRequest", mock.Anything, uint(1)).Return(req, nil)
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 1, 99)
	require.Error(t, err)
	// #G14: same generic "not found" a nonexistent request ID gets — a distinct
	// "not your access request" message would let a caller enumerate request IDs
	// that exist but belong to someone else.
	assert.Contains(t, err.Error(), "access request not found")
}

func TestWithdrawAccessRequest_NotPending(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 1, UserID: 5, State: AccessRequestApproved}
	ms.On("GetAccessRequest", mock.Anything, uint(1)).Return(req, nil)
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 1, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending request can be withdrawn")
}

func TestWithdrawAccessRequest_UpdateError(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 1, UserID: 5, State: AccessRequestPending, ProjectID: 3}
	ms.On("GetAccessRequest", mock.Anything, uint(1)).Return(req, nil)
	ms.On("UpdateAccessRequest", mock.Anything, mock.AnythingOfType("*models.AccessRequest")).Return(false, errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestWithdrawAccessRequest_ConcurrentApproval(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 1, UserID: 5, State: AccessRequestPending, ProjectID: 3}
	ms.On("GetAccessRequest", mock.Anything, uint(1)).Return(req, nil)
	// UpdateAccessRequest returns ok=false (race condition).
	ms.On("UpdateAccessRequest", mock.Anything, mock.AnythingOfType("*models.AccessRequest")).Return(false, nil)
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 1, 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no longer pending")
}

func TestWithdrawAccessRequest_Success(t *testing.T) {
	ms := new(MockStorage)
	req := &models.AccessRequest{ID: 1, UserID: 5, State: AccessRequestPending, ProjectID: 3}
	ms.On("GetAccessRequest", mock.Anything, uint(1)).Return(req, nil)
	ms.On("UpdateAccessRequest", mock.Anything, mock.AnythingOfType("*models.AccessRequest")).Return(true, nil)
	ms.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	c := NewKeyorixCore(ms)
	err := c.WithdrawAccessRequest(context.Background(), 1, 5)
	require.NoError(t, err)
}

// ── sod.go — requireMachineGrantNoSoDViolation ───────────────────────────

func TestRequireMachineGrantNoSoDViolation_ListPoliciesError(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListSoDPolicies", mock.Anything).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 2)
	require.Error(t, err)
}

func TestRequireMachineGrantNoSoDViolation_NoPolicies(t *testing.T) {
	ms := new(MockStorage)
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{}, nil)
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 2)
	require.NoError(t, err)
}

func TestRequireMachineGrantNoSoDViolation_RoleError(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	ms.On("GetRole", mock.Anything, uint(5)).Return(nil, errors.New("role not found"))
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 5)
	require.Error(t, err)
}

func TestRequireMachineGrantNoSoDViolation_AdminRoleSkipsSoD(t *testing.T) {
	ms := new(MockStorage)
	policy := &models.SoDPolicy{ID: 1}
	ms.On("ListSoDPolicies", mock.Anything).Return([]*models.SoDPolicy{policy}, nil)
	// "global_admin" is an admin role → requireMachineGrantNoSoDViolation returns nil.
	ms.On("GetRole", mock.Anything, uint(5)).Return(&models.Role{ID: 5, Name: "global_admin"}, nil)
	c := NewKeyorixCore(ms)
	err := c.requireMachineGrantNoSoDViolation(context.Background(), 1, 5)
	require.NoError(t, err)
}

// ── auth.go — Login MFA required path ────────────────────────────────────

func TestLogin_MFARequired(t *testing.T) {
	ms := new(MockStorage)
	// MFA-enabled user: create a bcrypt hash so VerifyPasswordCredentials succeeds.
	hash, err := bcrypt.GenerateFromPassword([]byte("Password#Str0ng!"), bcrypt.MinCost)
	require.NoError(t, err)
	user := &models.User{
		ID:           1,
		Username:     "mfauser",
		Email:        "mfa@x.com",
		PasswordHash: string(hash),
		IsActive:     true,
		AccountState: "active",
		MFAEnabled:   true,
	}
	ms.On("GetUserByUsername", mock.Anything, "mfauser").Return(user, nil)
	// Login calls VerifyPasswordCredentials → GetUserByUsername already mocked.
	c := NewKeyorixCore(ms)
	_, u, loginErr := c.Login(context.Background(), &LoginRequest{Username: "mfauser", Password: "Password#Str0ng!"})
	require.ErrorIs(t, loginErr, ErrMFARequired)
	assert.Equal(t, uint(1), u.ID)
}

// ── access_review_campaign.go — OpenAccessReviewCampaign ─────────────────

func TestOpenAccessReviewCampaign_ZeroProjectID_s30(t *testing.T) {
	c := NewKeyorixCore(new(MockStorage))
	// actorID=1, projectID=0 → returns "project ID is required" immediately.
	_, err := c.OpenAccessReviewCampaign(context.Background(), 1, 0, 0, "Campaign")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project ID is required")
}

// ── access_review_campaign.go — CloseAccessReviewCampaign ────────────────

func TestCloseAccessReviewCampaign_CampaignNotFound(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetAccessReviewCampaign", mock.Anything, uint(5)).Return(nil, errors.New("not found"))
	c := NewKeyorixCore(ms)
	_, err := c.CloseAccessReviewCampaign(context.Background(), 1, 0, 1, 5, false)
	require.Error(t, err)
}

func TestCloseAccessReviewCampaign_WrongProject(t *testing.T) {
	ms := new(MockStorage)
	campaign := &models.AccessReviewCampaign{ID: 5, ProjectID: 99, State: CampaignStateOpen}
	ms.On("GetAccessReviewCampaign", mock.Anything, uint(5)).Return(campaign, nil)
	c := NewKeyorixCore(ms)
	// projectID=1 but campaign has ProjectID=99 → scoping error.
	_, err := c.CloseAccessReviewCampaign(context.Background(), 1, 0, 1, 5, false)
	require.Error(t, err)
}

// ── access_review_campaign.go — userInGroup ──────────────────────────────

func TestUserInGroup_StorageError(t *testing.T) {
	ms := new(MockStorage)
	// userInGroup calls GetUserGroups(ctx, userID=5) — on error, returns true (fail open).
	ms.On("GetUserGroups", mock.Anything, uint(5)).Return(nil, errors.New("db error"))
	c := NewKeyorixCore(ms)
	result := c.userInGroup(context.Background(), 5, 1)
	// On error, userInGroup returns true (fail safe).
	assert.True(t, result)
}

func TestUserInGroup_Found(t *testing.T) {
	ms := new(MockStorage)
	groups := []*models.Group{{ID: 1, Name: "admins"}}
	ms.On("GetUserGroups", mock.Anything, uint(5)).Return(groups, nil)
	c := NewKeyorixCore(ms)
	result := c.userInGroup(context.Background(), 5, 1)
	assert.True(t, result)
}

func TestUserInGroup_NotFound(t *testing.T) {
	ms := new(MockStorage)
	groups := []*models.Group{{ID: 99, Name: "others"}}
	ms.On("GetUserGroups", mock.Anything, uint(5)).Return(groups, nil)
	c := NewKeyorixCore(ms)
	result := c.userInGroup(context.Background(), 5, 1)
	assert.False(t, result)
}
