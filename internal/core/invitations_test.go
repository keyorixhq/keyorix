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
	store.On("GetProjectInvitation", ctx, uint(7)).Return(&models.ProjectInvitation{ID: 7, State: InvitationAccepted}, nil)

	err := c.RevokeInvitation(ctx, 7, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
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

	allowNotifications(store) // best-effort outcome notification to the requester
	out, err := c.ApproveAccessRequest(ctx, 3, 9, "project_developer")
	require.NoError(t, err)
	assert.Equal(t, AccessRequestApproved, out.State)
	store.AssertCalled(t, "AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
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

	allowNotifications(store) // best-effort outcome notification to the requester
	// Empty grantedRole → uses the suggested role.
	out, err := c.ApproveAccessRequest(ctx, 3, 9, "")
	require.NoError(t, err)
	assert.Equal(t, "project_viewer", out.GrantedRole)
}

func TestApproveAccessRequest_RejectsNonPending(t *testing.T) {
	store := new(MockStorage)
	c := newInviteCore(store)
	ctx := context.Background()
	store.On("GetAccessRequest", ctx, uint(3)).Return(&models.AccessRequest{ID: 3, State: AccessRequestApproved}, nil)

	_, err := c.ApproveAccessRequest(ctx, 3, 9, "project_viewer")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only a pending")
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
