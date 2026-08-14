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

// ADR-022's domain allowlist previously only gated the email-based
// InviteToProject/InviteGlobal flow — InviteMember (the userID-keyed invite
// path) bypassed it entirely. Verify it's now enforced here too.
func TestInviteMember_RejectsDisallowedDomain(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	c.membershipDomainAllowlist = []string{"allowed.com"}
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5, Name: "project_developer"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Email: "outsider@evil.com"}, nil)

	_, err := c.InviteMember(ctx, 1, 2, "project_developer", 9, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not on the allowlist")
	store.AssertNotCalled(t, "CreateProjectMembership", mock.Anything, mock.Anything)
}

// TestDomainAllowed_RejectsMalformedMultiAtEmail is #G46: domainAllowed used to extract
// the domain via strings.LastIndex(email, "@"), which silently accepts a malformed
// multi-'@' address like "attacker@evil.com@allowed.com" and reports "allowed.com" (its
// trailing segment) as the domain — a parser-differential risk if any downstream mail/
// identity consumer of the same raw string parses '@' differently. A well-formed email
// has exactly one '@'; anything else must be rejected outright, not domain-guessed.
func TestDomainAllowed_RejectsMalformedMultiAtEmail(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	c.membershipDomainAllowlist = []string{"allowed.com"}

	adversarial := []string{
		"attacker@evil.com@allowed.com",
		"attacker@allowed.com@evil.com",
		"@allowed.com",
		"user@",
		"nodomainatall",
	}
	for _, email := range adversarial {
		assert.False(t, c.domainAllowed(email), "%q must be rejected as malformed, not domain-guessed", email)
	}
	assert.True(t, c.domainAllowed("user@allowed.com"), "a well-formed single-'@' email on the allowlist must still pass")
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
		Return(&models.ProjectMembership{ID: 50, ProjectID: 1, State: MembershipInvited}, nil)

	_, err := c.TransitionMembership(ctx, 1, 50, MembershipActive, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot transition")
	store.AssertNotCalled(t, "TransitionProjectMembershipState", mock.Anything, mock.Anything, mock.Anything)
}

// TestInviteMember_OpenActivationFailure_RevertsOrphanedActiveMembership is the
// (#309) losing-racer regression: open-mode InviteMember commits a `state=active`
// ProjectMembership row first, then grants the role. This deterministically
// simulates the losing racer of a concurrent invite race (or any other path that
// already holds the role independently of this membership) by making the role
// grant itself fail with the exact composite-primary-key rejection message a real
// SQLite/Postgres backend returns ("Role already assigned") — reproducing the
// interleaving without needing real goroutines. It asserts (a) the caller still
// sees the error (existing, correct behavior) and (b) the just-created row no
// longer reads as active — it must not survive as an orphaned "ghost" active
// membership behind a reported failure.
func TestInviteMember_OpenActivationFailure_RevertsOrphanedActiveMembership(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	c.membershipValidationMode = ValidationModeOpen
	ctx := context.Background()

	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6, Name: "project_viewer"}, nil)
	store.On("GetActiveProjectMembership", ctx, uint(1), uint(2)).Return(nil, fmt.Errorf("not found"))
	created := &models.ProjectMembership{ID: 51, ProjectID: 1, UserID: 2, Role: "project_viewer", State: MembershipActive}
	store.On("CreateProjectMembership", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.State == MembershipActive && m.ProjectID == 1 && m.UserID == 2
	})).Return(created, nil)
	// The composite user_roles primary key rejects the grant — the losing racer (or
	// any caller whose role is already held via an independent path).
	store.On("AssignRole", ctx, uint(2), uint(6), storage.Scope{ProjectID: 1}).
		Return(fmt.Errorf("Role already assigned"))
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.ID == 51 && m.State == MembershipRevoked && m.RevokedAt != nil
	}), MembershipActive).Return(true, nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	m, err := c.InviteMember(ctx, 1, 2, "project_viewer", 9, false)

	// (a) the error still propagates to the caller.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to grant role on activation")
	assert.Nil(t, m)

	// (b) the just-created row was actually reverted, not left standing active.
	store.AssertNumberOfCalls(t, "TransitionProjectMembershipState", 1)
	assert.Equal(t, MembershipRevoked, created.State, "orphaned row must not still read as active")
	assert.NotNil(t, created.RevokedAt)
}

// TestTransitionMembership_ActivationFailure_RevertsToPriorState is the (#309)
// companion for the non-Open validation modes: an admin's explicit
// TransitionMembership(..., MembershipActive, ...) call persists `active` first,
// then grants the role — the identical ordering, and identical orphan risk, as
// inviteMemberWithMode. Unlike a brand-new invite, this row already existed in a
// legitimate pending state before the failed activation attempt, so the revert
// must restore THAT state (leaving the membership retriable) rather than jumping
// straight to the terminal `revoked` state.
func TestTransitionMembership_ActivationFailure_RevertsToPriorState(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()

	existing := &models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, Role: "project_viewer", State: MembershipProvisioned}
	store.On("GetProjectMembership", ctx, uint(50)).Return(existing, nil)
	store.On("GetRoleByName", ctx, "project_viewer").Return(&models.Role{ID: 6, Name: "project_viewer"}, nil)
	// First write: persists the (about to be reverted) active state.
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.ID == 50 && m.State == MembershipActive
	}), MembershipProvisioned).Return(true, nil).Once()
	store.On("AssignRole", ctx, uint(2), uint(6), storage.Scope{ProjectID: 1}).
		Return(fmt.Errorf("Role already assigned"))
	// Revert write: must go back to `provisioned`, not `revoked`.
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(m *models.ProjectMembership) bool {
		return m.ID == 50 && m.State == MembershipProvisioned
	}), MembershipActive).Return(true, nil).Once()
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	m, err := c.TransitionMembership(ctx, 1, 50, MembershipActive, 9)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to grant role on activation")
	assert.Nil(t, m)
	assert.Equal(t, MembershipProvisioned, existing.State, "must revert to the pre-transition state, not stay active or jump to revoked")
	store.AssertNumberOfCalls(t, "TransitionProjectMembershipState", 2)
}

// Cross-project guard: a membership in project 2 must not be transitionable when
// the caller is authorized for project 1 (would otherwise grant a role in 2).
func TestTransitionMembership_RejectsOtherProject(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	store.On("GetProjectMembership", ctx, uint(50)).
		Return(&models.ProjectMembership{ID: 50, ProjectID: 2, UserID: 2, Role: "project_admin", State: MembershipProvisioned}, nil)

	_, err := c.TransitionMembership(ctx, 1, 50, MembershipActive, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
	store.AssertNotCalled(t, "TransitionProjectMembershipState", mock.Anything, mock.Anything, mock.Anything)
	store.AssertNotCalled(t, "AssignRole", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestTransitionMembership_ActivateGrantsRole(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	m := &models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, Role: "project_developer", State: MembershipProvisioned}
	store.On("GetProjectMembership", ctx, uint(50)).Return(m, nil)
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipActive && x.ActivatedAt != nil
	}), MembershipProvisioned).Return(true, nil)
	store.On("GetRoleByName", ctx, "project_developer").Return(&models.Role{ID: 5}, nil)
	store.On("AssignRole", ctx, uint(2), uint(5), storage.Scope{ProjectID: 1}).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	out, err := c.TransitionMembership(ctx, 1, 50, MembershipActive, 9)
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
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipRevoked && x.RevokedAt != nil
	}), MembershipActive).Return(true, nil)
	// RemoveProjectMember resolves and drops the role grant (best-effort). The
	// role (5) doesn't carry roles.assign, so the last-admin guard (#236) is a
	// fast no-op. ListProjectRoleAssignments is still consulted unconditionally
	// to build the per-grant RBAC audit trail (#234) before the bulk delete.
	store.On("GetUserRoleIDsExact", ctx, uint(2), storage.Scope{ProjectID: 1}).Return([]uint{5}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "roles.assign").Return(false, nil)
	store.On("ListProjectRoleAssignments", ctx, uint(1)).Return([]storage.RoleAssignment{
		{PrincipalType: "user", PrincipalID: 2, RoleID: 5, ProjectID: 1},
	}, nil)
	store.On("RemoveAllProjectRoleGrants", ctx, uint(2), uint(1)).Return(nil)
	store.On("ClearProjectSecretOwnership", ctx, uint(2), uint(1)).Return(nil)
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	out, err := c.TransitionMembership(ctx, 1, 50, MembershipRevoked, 9)
	require.NoError(t, err)
	assert.Equal(t, MembershipRevoked, out.State)
	store.AssertCalled(t, "RemoveAllProjectRoleGrants", ctx, uint(2), uint(1))
	store.AssertCalled(t, "ClearProjectSecretOwnership", ctx, uint(2), uint(1))
}

// TestTransitionMembership_RevokeRefusedForLastAdmin_RevertsAndReturnsError is
// #G54: RemoveProjectMember's guardLastProjectAdmin refusal (the target is the
// project's last roles.assign holder) must not be silently swallowed. Before
// the fix, TransitionMembership discarded this error entirely — the
// membership row committed as `revoked` while the user's role grant (their
// actual access) stayed fully live, a security-relevant inconsistency. The
// fix must revert the membership back to its pre-transition state and
// surface the error.
func TestTransitionMembership_RevokeRefusedForLastAdmin_RevertsAndReturnsError(t *testing.T) {
	store := new(MockStorage)
	c := newMembershipCore(store)
	ctx := context.Background()
	m := &models.ProjectMembership{ID: 50, ProjectID: 1, UserID: 2, State: MembershipActive}
	store.On("GetProjectMembership", ctx, uint(50)).Return(m, nil)
	// First write: persists the (about to be reverted) revoked state.
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipRevoked
	}), MembershipActive).Return(true, nil).Once()
	// RemoveProjectMember's guardLastProjectAdmin: user 2 is the project's
	// only roles.assign holder, so removal is refused.
	store.On("GetUserRoleIDsExact", ctx, uint(2), storage.Scope{ProjectID: 1}).Return([]uint{5}, nil)
	store.On("RoleSetHasPermission", ctx, []uint{5}, "roles.assign").Return(true, nil)
	store.On("RoleSetHasPermission", ctx, []uint(nil), "roles.assign").Return(false, nil)
	store.On("ListProjectRoleAssignments", ctx, uint(1)).Return([]storage.RoleAssignment{
		{PrincipalType: "user", PrincipalID: 2, RoleID: 5, ProjectID: 1},
	}, nil)
	// Revert write: must go back to `active`, not stay revoked.
	store.On("TransitionProjectMembershipState", ctx, mock.MatchedBy(func(x *models.ProjectMembership) bool {
		return x.State == MembershipActive
	}), MembershipRevoked).Return(true, nil).Once()
	store.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	out, err := c.TransitionMembership(ctx, 1, 50, MembershipRevoked, 9)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to remove role grant on revocation")
	assert.Nil(t, out)
	assert.Equal(t, MembershipActive, m.State, "must revert to active, not leave the row revoked while the grant stays live")
	store.AssertNotCalled(t, "RemoveAllProjectRoleGrants", mock.Anything, mock.Anything, mock.Anything)
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
