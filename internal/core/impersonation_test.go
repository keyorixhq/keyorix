package core

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func newImpersonationCore(store *MockStorage) *KeyorixCore {
	fixed := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: store, now: func() time.Time { return fixed }}
}

func TestStartImpersonation_Success(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "alice", IsActive: true}, nil)
	// The target-rank guard discovers every scope the target holds a role at (it
	// holds none here), so no per-scope admin comparison ever runs.
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{}, nil)
	store.On("CreateSession", ctx, mock.MatchedBy(func(s *models.Session) bool {
		return s.UserID == 2 && s.ImpersonatedBy != nil && *s.ImpersonatedBy == 1 &&
			s.ImpersonationStartedAt != nil
	})).Return(&models.Session{ID: 99, UserID: 2, SessionToken: "tok"}, nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventImpersonationStart && e.Impersonation &&
			e.ImpersonatedBy != nil && *e.ImpersonatedBy == 1 &&
			e.ActingAs != nil && *e.ActingAs == 2
	})).Return(nil)

	session, target, err := c.StartImpersonation(ctx, 1, 2, "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session.SessionToken != "tok" || target.Username != "alice" {
		t.Errorf("unexpected result: session=%v target=%v", session, target)
	}
	store.AssertExpectations(t)
}

func TestStartImpersonation_RejectsSelf(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	if _, _, err := c.StartImpersonation(context.Background(), 5, 5, ""); err == nil {
		t.Fatal("expected an error impersonating yourself")
	}
}

// A request carrying a least-privilege PAT restriction may not start impersonation —
// otherwise the impersonation session (which carries no restriction) would launder the
// PAT's bound and act as the target with full permissions.
func TestStartImpersonation_RejectsRestrictedPAT(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := WithPATRestriction(context.Background(), &PATRestriction{Permissions: []string{"users.*"}})
	_, _, err := c.StartImpersonation(ctx, 1, 2, "")
	if err == nil || !strings.Contains(err.Error(), "restricted access token") {
		t.Fatalf("expected a restricted-token rejection, got %v", err)
	}
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A suspended/inactive target cannot be impersonated (the session would be dead on
// arrival and only emit a misleading audit event).
func TestStartImpersonation_RejectsInactiveTarget(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "alice", IsActive: false}, nil)
	_, _, err := c.StartImpersonation(ctx, 1, 2, "")
	if err == nil || !strings.Contains(err.Error(), "suspended or inactive") {
		t.Fatalf("expected an inactive-target rejection, got %v", err)
	}
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A non-admin caller cannot impersonate a global admin (privilege escalation guard).
func TestStartImpersonation_RejectsAdminTargetForNonAdminCaller(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "helpdesk"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "root", IsActive: true}, nil)
	// Target (id 2) holds the admin role globally; caller (id 1) holds nothing.
	store.On("GetRoleByName", ctx, mock.Anything).Return(&models.Role{ID: 7, Name: "admin"}, nil)
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{{}}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(2), mock.Anything).Return([]uint{7}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{}, nil)
	// #G05: the ceiling now compares the target's ACTUAL bundled permissions
	// (not the "admin" role name itself) against what the caller can exercise.
	store.On("GetRolePermissions", ctx, uint(7)).Return([]*models.Permission{{Name: "system.write"}}, nil)
	_, _, err := c.StartImpersonation(ctx, 1, 2, "")
	if err == nil || !strings.Contains(err.Error(), "which you do not also hold") {
		t.Fatalf("expected an admin-target rejection, got %v", err)
	}
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A non-admin caller cannot impersonate a target who holds an admin-tier role
// scoped to a single PROJECT (never itself flagged "global admin") — the
// scope-aware gap #165 closes beyond the older global-only check.
func TestStartImpersonation_RejectsProjectScopedAdminTargetForNonAdminCaller(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	projScope := Scope{ProjectID: 7}
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "helpdesk"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "proj-admin", IsActive: true}, nil)
	// Target (id 2) holds project_admin at project 7 only; caller (id 1) holds nothing.
	store.On("GetRoleByName", ctx, mock.Anything).Return(&models.Role{ID: 8, Name: "project_admin"}, nil)
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{projScope}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(2), projScope).Return([]uint{8}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), projScope).Return([]uint{}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(1), projScope).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), projScope).Return([]uint{}, nil)
	store.On("GetRolePermissions", ctx, uint(8)).Return([]*models.Permission{{Name: "roles.assign"}}, nil)
	_, _, err := c.StartImpersonation(ctx, 1, 2, "")
	if err == nil || !strings.Contains(err.Error(), "which you do not also hold") {
		t.Fatalf("expected a project-scoped admin-target rejection, got %v", err)
	}
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// A caller who ALSO holds project_admin at the target's exact project scope may
// impersonate a project-scoped admin target — the ceiling is satisfied, not
// unconditionally blocked.
func TestStartImpersonation_AllowsProjectScopedAdminTargetForSameScopeAdminCaller(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	projScope := Scope{ProjectID: 7}
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "other-proj-admin"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "proj-admin", IsActive: true}, nil)
	store.On("GetRoleByName", ctx, mock.Anything).Return(&models.Role{ID: 8, Name: "project_admin"}, nil)
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{projScope}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(2), projScope).Return([]uint{8}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), projScope).Return([]uint{}, nil)
	// Caller also holds project_admin at the SAME project scope.
	store.On("GetUserRoleIDsAt", ctx, uint(1), projScope).Return([]uint{8}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), projScope).Return([]uint{}, nil)
	store.On("GetRolePermissions", ctx, uint(8)).Return([]*models.Permission{{Name: "roles.assign"}}, nil)
	store.On("CreateSession", ctx, mock.MatchedBy(func(s *models.Session) bool {
		return s.UserID == 2 && s.ImpersonatedBy != nil && *s.ImpersonatedBy == 1
	})).Return(&models.Session{ID: 100, UserID: 2, SessionToken: "tok2"}, nil)
	store.On("LogAuditEvent", ctx, mock.Anything).Return(nil)

	session, target, err := c.StartImpersonation(ctx, 1, 2, "")
	require.NoError(t, err)
	require.Equal(t, "tok2", session.SessionToken)
	require.Equal(t, "proj-admin", target.Username)
}

// A non-admin caller cannot impersonate a target whose admin-tier authority
// comes from a CUSTOM role (not one of the fixed adminRoleNames) that bundles
// an admin-tier permission — #G05's exact regression for the old role-NAME
// check, which silently skipped the ceiling entirely for any role it didn't
// recognize by name, no matter how privileged its actual permission bundle.
func TestStartImpersonation_RejectsCustomAdminTierRoleTargetForNonAdminCaller(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "helpdesk"}, nil)
	store.On("GetUser", ctx, uint(2)).Return(&models.User{ID: 2, Username: "secops", IsActive: true}, nil)
	// Target (id 2) holds a custom "secops" role (id 9) at global scope, bundling
	// system.write — never named in adminRoleNames, so roleSetContainsAdmin(target)
	// would have returned false and the old check would have skipped this scope.
	store.On("GetRoleByName", ctx, mock.Anything).Return((*models.Role)(nil), fmt.Errorf("not found"))
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{{}}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(2), mock.Anything).Return([]uint{9}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(2), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), mock.Anything).Return([]uint{}, nil)
	store.On("GetRolePermissions", ctx, uint(9)).Return([]*models.Permission{{Name: "system.write"}}, nil)
	_, _, err := c.StartImpersonation(ctx, 1, 2, "")
	if err == nil || !strings.Contains(err.Error(), "which you do not also hold") {
		t.Fatalf("expected a custom-admin-tier-role rejection, got %v", err)
	}
	store.AssertNotCalled(t, "CreateSession", mock.Anything, mock.Anything)
}

// #G05 detection_idea: revoke the impersonator's users.impersonate mid-session
// (the admin keeps every OTHER permission — this is deliberately NOT a rank
// demotion, to isolate the missing check) — ReauthorizeImpersonation (the
// function ValidateSessionToken calls on every request against an active
// impersonation session, and StreamAuditLogs' re-auth ticker calls for gRPC)
// must now refuse, so the session is terminated within one re-auth cycle
// rather than remaining valid for the rest of its TTL.
func TestReauthorizeImpersonation_RevokedImpersonatePermission(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin", IsActive: true}, nil)
	// Admin (1) no longer holds users.impersonate: RoleSetHasPermission returns
	// false for it, but the admin otherwise still outranks the target (2, no
	// roles at all) — isolates the missing per-permission re-check from the
	// pre-existing rank-ceiling re-check.
	store.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{}, nil)
	store.On("GetRoleByName", ctx, mock.Anything).Return((*models.Role)(nil), fmt.Errorf("not found"))
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(false, nil)
	err := c.ReauthorizeImpersonation(ctx, 1, 2)
	if err == nil || !strings.Contains(err.Error(), "impersonation authority has been revoked") {
		t.Fatalf("expected a revoked-impersonate-permission rejection, got %v", err)
	}
}

// The companion positive case: an admin who still holds users.impersonate and
// still outranks the target passes re-authorization.
func TestReauthorizeImpersonation_StillAuthorized(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin", IsActive: true}, nil)
	store.On("GetUserRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{5}, nil)
	store.On("GetUserGroupRoleIDsAt", ctx, uint(1), Scope{}).Return([]uint{}, nil)
	store.On("GetRoleByName", ctx, mock.Anything).Return((*models.Role)(nil), fmt.Errorf("not found"))
	store.On("RoleSetHasPermission", ctx, []uint{5}, "users.impersonate").Return(true, nil)
	store.On("GetUserRoleScopes", ctx, uint(2)).Return([]Scope{}, nil)
	err := c.ReauthorizeImpersonation(ctx, 1, 2)
	require.NoError(t, err)
}

// A suspended/deactivated admin fails re-authorization even if their role
// grants are otherwise untouched (the pre-existing account-state half of
// MT-007, still exercised through the shared ReauthorizeImpersonation path).
func TestReauthorizeImpersonation_SuspendedAdmin(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetUser", ctx, uint(1)).Return(&models.User{ID: 1, Username: "admin", IsActive: false}, nil)
	err := c.ReauthorizeImpersonation(ctx, 1, 2)
	if err == nil || !strings.Contains(err.Error(), "not active") {
		t.Fatalf("expected a suspended-admin rejection, got %v", err)
	}
}

func TestEndImpersonation_LogsDurationAndActionCount(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()

	started := c.now().Add(-2 * time.Minute)
	admin := uint(1)
	store.On("GetSession", ctx, "tok").Return(&models.Session{
		ID: 99, UserID: 2, ImpersonatedBy: &admin, ImpersonationStartedAt: &started,
	}, nil)
	store.On("CountImpersonatedActions", uint(2), uint(1), started).Return(int64(3), nil)
	store.On("LogAuditEvent", ctx, mock.MatchedBy(func(e *models.AuditEvent) bool {
		return e.EventType == EventImpersonationEnd && e.Impersonation &&
			strings.Contains(e.Diff, `"action_count":3`) &&
			strings.Contains(e.Diff, `"duration_seconds":120`)
	})).Return(nil)
	store.On("DeleteSession", ctx, uint(99)).Return(nil)

	if err := c.EndImpersonation(ctx, "tok"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	store.AssertExpectations(t)
}

func TestEndImpersonation_RejectsNonImpersonationSession(t *testing.T) {
	store := new(MockStorage)
	c := newImpersonationCore(store)
	ctx := context.Background()
	store.On("GetSession", ctx, "tok").Return(&models.Session{ID: 1, UserID: 2}, nil)

	if err := c.EndImpersonation(ctx, "tok"); err == nil {
		t.Fatal("expected an error for a non-impersonation session")
	}
}
