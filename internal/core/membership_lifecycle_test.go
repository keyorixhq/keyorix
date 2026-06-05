package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newMembershipCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
	return c
}

func TestCanTransition(t *testing.T) {
	valid := [][2]string{
		{MembershipInvited, MembershipIdentityVerified},
		{MembershipIdentityVerified, MembershipProvisioned},
		{MembershipProvisioned, MembershipActive},
		{MembershipInvited, MembershipRevoked},
		{MembershipActive, MembershipRevoked},
	}
	for _, tc := range valid {
		assert.True(t, canTransition(tc[0], tc[1]), "%s→%s should be allowed", tc[0], tc[1])
	}
	invalid := [][2]string{
		{MembershipInvited, MembershipProvisioned}, // can't skip
		{MembershipInvited, MembershipActive},
		{MembershipRevoked, MembershipInvited}, // terminal
		{MembershipRevoked, MembershipActive},
		{MembershipActive, MembershipProvisioned}, // no going back
	}
	for _, tc := range invalid {
		assert.False(t, canTransition(tc[0], tc[1]), "%s→%s should be rejected", tc[0], tc[1])
	}
}

func TestInitialMembershipStateForMode(t *testing.T) {
	assert.Equal(t, MembershipActive, initialMembershipStateForMode(ValidationModeOpen, false))
	assert.Equal(t, MembershipInvited, initialMembershipStateForMode(ValidationModeAllowlist, true))
	assert.Equal(t, MembershipProvisioned, initialMembershipStateForMode(ValidationModeIDP, true), "idp-resolved skips early states")
	assert.Equal(t, MembershipInvited, initialMembershipStateForMode(ValidationModeIDP, false), "non-idp starts invited")
	assert.Equal(t, MembershipInvited, initialMembershipStateForMode("", false), "empty/unknown falls back to allowlist")
}

func TestInviteMember_AllowlistStartsInvited(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	c.membershipValidationMode = ValidationModeAllowlist
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	store.On("GetActiveProjectMembership", ctx, uint(1), uint(2)).Return(nil, fmt.Errorf("not found"))
	store.On("CreateProjectMembership", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.State == MembershipInvited && m.ProjectID == 1 && m.UserID == 2 && m.InvitedBy == 9
	})).Return(&models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, State: MembershipInvited}, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	m, err := c.InviteMember(ctx, 1, 2, "project_developer", 9, false)
	require.NoError(t, err)
	assert.Equal(t, MembershipInvited, m.State)
	// No role granted yet in allowlist mode.
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestInviteMember_OpenGrantsRoleImmediately(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	c.membershipValidationMode = ValidationModeOpen
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	store.On("GetActiveProjectMembership", ctx, uint(1), uint(2)).Return(nil, fmt.Errorf("not found"))
	store.On("CreateProjectMembership", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.State == MembershipActive && m.ActivatedAt != nil
	})).Return(&models.ProjectMembership{ID: 51, ProjectID: 1, UserID: 2, Role: "project_developer", State: MembershipActive}, nil)
	// Active → role granted: AddProjectMember resolves the role and assigns it.
	store.On("AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	m, err := c.InviteMember(ctx, 1, 2, "project_developer", 9, false)
	require.NoError(t, err)
	assert.Equal(t, MembershipActive, m.State)
	store.AssertCalled(t, "AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
}

func TestInviteMember_RejectsDuplicate(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6, Name: "project_viewer"}, nil)
	store.On("GetActiveProjectMembership", ctx, uint(1), uint(2)).
		Return(&models.ProjectMembership{ID: 1, State: MembershipActive}, nil)

	_, err := c.InviteMember(ctx, 1, 2, "project_viewer", 9, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already has")
	store.AssertNotCalled(t, "CreateProjectMembership", mock.Anything, mock.Anything)
}

func TestTransitionMembership_RejectsIllegalJump(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	store.On("GetProjectMembership", ctx, uint(50)).
		Return(&models.ProjectMembership{ID: 50, State: MembershipInvited}, nil)

	_, err := c.TransitionMembership(ctx, 50, MembershipActive, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot transition")
	store.AssertNotCalled(t, "UpdateProjectMembership", mock.Anything, mock.Anything)
}

func TestTransitionMembership_ActivateGrantsRole(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	m := &models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, Role: "project_developer", State: MembershipProvisioned}
	store.On("GetProjectMembership", ctx, uint(50)).Return(m, nil)
	store.On("UpdateProjectMembership", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipActive && x.ActivatedAt != nil
	})).Return(nil)
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5}, nil)
	store.On("AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	out, err := c.TransitionMembership(ctx, 50, MembershipActive, 9)
	require.NoError(t, err)
	assert.Equal(t, MembershipActive, out.State)
	store.AssertCalled(t, "AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
}

func TestTransitionMembership_RevokeRemovesRole(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	m := &models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, State: MembershipActive}
	store.On("GetProjectMembership", ctx, uint(50)).Return(m, nil)
	store.On("UpdateProjectMembership", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipRevoked && x.RevokedAt != nil
	})).Return(nil)
	// RemoveProjectMember resolves and drops the role grant (best-effort).
	store.On("GetUserRoleIDsExact", ctx, uint(2), storage.Scope{ProjectID: 1}).Return([]uint{5}, nil)
	store.On("RemoveRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	out, err := c.TransitionMembership(ctx, 50, MembershipRevoked, 9)
	require.NoError(t, err)
	assert.Equal(t, MembershipRevoked, out.State)
	store.AssertCalled(t, "RemoveRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1})
}

func TestStaleInvites_PassesCutoff(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	want := c.now().Add(-7 * 24 * time.Hour)
	store.On("ListStaleInvitedMemberships", ctx, want).
		Return([]*models.ProjectMembership{{ID: 1, State: MembershipInvited}}, nil)

	out, err := c.StaleInvites(ctx, 7*24*time.Hour)
	require.NoError(t, err)
	assert.Len(t, out, 1)
	store.AssertCalled(t, "ListStaleInvitedMemberships", ctx, want)
}
