package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newInviteCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestInviteToProject(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5}, nil)
	store.On("CreateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.State == InvitationPending && inv.Email == "a@b.com" && inv.ProjectID == 1 && inv.ExpiresAt != nil
	})).Return(&models.ProjectInvitation{ID: 7, State: InvitationPending}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "invitation.created"
	})).Return(nil)

	inv, err := c.InviteToProject(ctx, 1, "a@b.com", "project_developer", 9)
	require.NoError(t, err)
	assert.Equal(t, InvitationPending, inv.State)
	store.AssertExpectations(t)
}

func TestRevokeInvitation_RejectsNonPending(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetProjectInvitation", ctx, uint(7)).Return(&models.ProjectInvitation{ID: 7, ProjectID: 1, State: InvitationAccepted}, nil)

	err := c.RevokeInvitation(ctx, 1, 7, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
	store.AssertNotCalled(t, "UpdateProjectInvitation", mock.Anything, mock.Anything)
}

// Cross-project guard: revoking an invitation in project 2 while authorized for
// project 1 must be rejected.
func TestRevokeInvitation_RejectsOtherProject(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetProjectInvitation", ctx, uint(7)).Return(&models.ProjectInvitation{ID: 7, ProjectID: 2, State: InvitationPending}, nil)

	err := c.RevokeInvitation(ctx, 1, 7, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "UpdateProjectInvitation", mock.Anything, mock.Anything)
}

func TestApproveAccessRequest_GrantsRole(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending,
	}, nil)
	// Admin upgrades the grant to developer.
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5}, nil)
	store.On("AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.MatchedBy(func(r *models.AccessRequest) bool {
		return r.State == AccessRequestApproved && r.GrantedRole == "project_developer" && r.ResolvedBy == 9
	})).Return(nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == "access_request.approved"
	})).Return(nil)
	// The grant now also routes through the audited RBAC choke point (#298), which
	// records its own structured role.assigned event alongside the generic one above.
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleAssigned
	})).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)

	allowNotifications(store) // best-effort outcome notification to the requester
	out, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "project_developer")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, out.State)
	store.AssertCalled(t, "AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
	store.AssertCalled(t, "LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventRoleAssigned
	}))
}

func TestApproveAccessRequest_FallsBackToSuggestedRole(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending,
	}, nil)
	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6}, nil)
	store.On("AssignRole", ctx, uint(2), uint(6), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.Anything).Return(nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)

	allowNotifications(store) // best-effort outcome notification to the requester
	// Empty grantedRole → uses the suggested role.
	out, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "")
	require.NoError(t, err)
	assert.Equal(t, "project_viewer", out.GrantedRole)
}

// stubAdminRoleLookups registers the admin role names so roleSetContainsAdmin can
// resolve them; super_admin=1, admin=2, system_admin=3, project_admin=4.
func stubAdminRoleLookups(store *MockStorage, ctx context.Context) {
	store.On("GetRoleByName", ctx, "super_admin").Return(&models.Role{ID: 1}, nil)
	store.On("GetRoleByName", ctx, "admin").Return(&models.Role{ID: 2}, nil)
	store.On("GetRoleByName", ctx, "system_admin").Return(&models.Role{ID: 3}, nil)
	store.On("GetRoleByName", ctx, "project_admin").Return(&models.Role{ID: 4}, nil)
}

// The same admin-role ceiling applies to project invitations: a non-admin inviter
// (roles.assign but not admin) cannot invite someone as an admin role — escalation-by-
// proxy. A non-admin role invite still works.
func TestInviteToProject_EnforcesAdminCeiling(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	stubAdminRoleLookups(store, ctx)
	// Inviter 9 holds only a non-admin role (id 6) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{6}, nil)

	// Inviting as project_admin → refused before any invitation is created.
	_, err := c.InviteToProject(ctx, 1, "a@b.io", "project_admin", 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only an administrator can grant")
	store.AssertNotCalled(t, "CreateProjectInvitation", mock.Anything, mock.Anything)

	// Inviting as a non-admin role is allowed (isAdminRoleName false → no ceiling).
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 6, Name: "project_developer"}, nil)
	store.On("CreateProjectInvitation", ctx, mock.Anything).Return(&models.ProjectInvitation{ID: 1}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)
	_, err = c.InviteToProject(ctx, 1, "c@d.io", "project_developer", 9)
	require.NoError(t, err)
}

// Privilege ceiling: a non-admin approver cannot sign off a request that grants an
// admin role — that would mint a principal more powerful than the approver.
func TestApproveAccessRequest_RejectsAdminGrantByNonAdmin(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "admin", State: AccessRequestPending,
	}, nil)
	stubAdminRoleLookups(store, ctx)
	// Approver 9 holds only a non-admin role (id 6) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{6}, nil)

	_, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only an administrator can grant")
	// The grant was refused before any role assignment or approval record.
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "CreateAccessRequestApproval", mock.Anything, mock.Anything)
}

// An admin approver may grant an admin role — the ceiling permits an equal-or-higher
// authority to sign off.
func TestApproveAccessRequest_AdminApproverMayGrantAdmin(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "admin", State: AccessRequestPending,
	}, nil)
	stubAdminRoleLookups(store, ctx)
	// Approver 9 holds the admin role (id 2) at the project.
	store.On("GetUserRoleIDsAt", ctx, uint(9), storage.Scope{ProjectID: 1}).Return([]uint{2}, nil)
	store.On("AssignRole", ctx, uint(2), uint(2), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("UpdateAccessRequest", ctx, mock.Anything).Return(nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)
	store.On("ListAccessRequestApprovals", ctx, uint(3)).Return([]*models.AccessRequestApproval{}, nil)
	store.On("CreateAccessRequestApproval", ctx, mock.Anything).Return(nil)
	allowNotifications(store)

	out, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "admin")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, out.State)
}

// A request whose TTL has elapsed is refused on the approve path (lazy expiry), not
// only on the list path — GetAccessRequest returns the stored record verbatim.
func TestApproveAccessRequest_RejectsExpired(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	past := time.Date(2026, 6, 5, 11, 0, 0, 0, time.UTC) // before the fixed clock (12:00)
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 1, UserID: 2, SuggestedRole: "project_viewer", State: AccessRequestPending, ExpiresAt: &past,
	}, nil)
	store.On("UpdateAccessRequest", ctx, mock.MatchedBy(func(r *models.AccessRequest) bool {
		return r.State == AccessRequestExpired
	})).Return(nil)

	_, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestApproveAccessRequest_RejectsNonPending(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{ID: 3, ProjectID: 1, State: AccessRequestApproved}, nil)

	_, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "project_viewer")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Cross-project guard: approving a request that belongs to project 2 while the
// caller is authorized for project 1 must be rejected — otherwise the role grant
// lands in a project the caller has no rights over (privilege escalation).
func TestApproveAccessRequest_RejectsOtherProject(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{
		ID: 3, ProjectID: 2, UserID: 2, SuggestedRole: "project_admin", State: AccessRequestPending,
	}, nil)

	_, err := c.ApproveAccessRequest(ctx, 1, 3, 9, "project_admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestWithdrawAccessRequest_OwnershipChecked(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{ID: 3, UserID: 2, State: AccessRequestPending}, nil)

	// A different user cannot withdraw it.
	err := c.WithdrawAccessRequest(ctx, 3, 99)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not your")
	store.AssertNotCalled(t, "UpdateAccessRequest", mock.Anything, mock.Anything)
}

func TestListProjectInvitations_LazyExpire(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	past := c.now().Add(-1 * time.Hour)
	store.On("ListProjectInvitations", ctx, uint(1)).Return([]*models.ProjectInvitation{
		{ID: 1, State: InvitationPending, ExpiresAt: &past},
	}, nil)
	// The expired pending invite is persisted as expired.
	store.On("UpdateProjectInvitation", ctx, mock.MatchedBy(func(inv *models.ProjectInvitation) bool {
		return inv.State == InvitationExpired
	})).Return(nil)

	out, err := c.ListProjectInvitations(ctx, 1)
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, InvitationExpired, out[0].State)
}

// Access-request approval grants a real role, so both the immediate and TTL-bound
// grant branches must land in the RBAC audit trail with a structured RoleID — not
// just the generic access_request.approved event (#298). Uses real storage so
// ListRBACAuditLogs is exercised end to end.
func TestApproveAccessRequestWithExpiry_IsRBACAudited(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	approver, err := st.CreateUser(ctx, &models.User{Username: "approver", Email: "approver@example.com", IsActive: true})
	require.NoError(t, err)
	requester, err := st.CreateUser(ctx, &models.User{Username: "requester", Email: "requester@example.com", IsActive: true})
	require.NoError(t, err)
	req, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: requester.ID, SuggestedRole: "project_viewer", State: AccessRequestPending,
	})
	require.NoError(t, err)

	_, err = c.ApproveAccessRequestWithExpiry(ctx, 1, req.ID, approver.ID, "", 0)
	require.NoError(t, err)

	entries, _, err := c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var assigned *RBACAuditEntry
	for _, e := range entries {
		if e.Action == EventRoleAssigned {
			assigned = e
		}
	}
	require.NotNil(t, assigned, "access-request approval grant must appear in the RBAC audit trail")
	require.NotNil(t, assigned.ActorUserID)
	assert.Equal(t, approver.ID, *assigned.ActorUserID)
	require.NotNil(t, assigned.TargetUserID)
	assert.Equal(t, requester.ID, *assigned.TargetUserID)

	// Time-bound (TTL) grant branch is audited the same way.
	req2, err := st.CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: 1, UserID: requester.ID, SuggestedRole: "project_developer", State: AccessRequestPending,
	})
	require.NoError(t, err)
	_, err = c.ApproveAccessRequestWithExpiry(ctx, 1, req2.ID, approver.ID, "", time.Hour)
	require.NoError(t, err)

	entries, _, err = c.ListRBACAuditLogs(ctx, 1, 50)
	require.NoError(t, err)
	var count int
	for _, e := range entries {
		if e.Action == EventRoleAssigned && e.TargetUserID != nil && *e.TargetUserID == requester.ID {
			count++
		}
	}
	assert.Equal(t, 2, count, "both the immediate and TTL-bound grants are RBAC-audited")
}
