// system_proxy_g3_gap_probes_test.go — live probes (not fixes) for the 8
// routes a content-level reconciliation of the never-merged
// fix/system-proxy-sweep-g2 branch against origin/main (fix/system-proxy-sweep-g3
// prep) found still open after #1968 (F5) and #1970 (9 /system proxy
// authority-ceiling gaps) landed.
//
// Each probe mints the WEAKEST principal that should be refused, drives the
// real route through a real HTTP server + real router + real auth
// middleware, and asserts by STATE DIFF (re-reading the row from storage
// after the request) whether the effect actually landed -- not merely the
// HTTP status code, per this repo's own standing rule ("to test a
// fails-open path, assert the effect, not the return value").
//
// For the membership/invitation/access-request routes, the weakest-refused
// principal is deliberately NOT "holds nothing" -- it is "holds roles.assign,
// but scoped to a DIFFERENT project than the one being mutated" (projectA),
// or "holds roles.assign at the right project, but the role being
// granted/activated bundles zero permissions" -- because a plain
// system.write-only caller with literally no roles.assign anywhere is
// already covered by the existing systemCeilingAllowlist reasoning in
// system_write_ceiling_walk_test.go for some of these routes (the reasoning
// cites a real, existing RequireGranterHoldsRolePermissions call). These
// probes target exactly what that reasoning misses.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// setupG3ProbeServer boots a fresh, isolated core + real HTTP server, per
// probe (no cross-test fixture sharing, matching this package's established
// convention).
func setupG3ProbeServer(t *testing.T) (*core.KeyorixCore, string) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newTestCore(t)
	createTestToken(t, c) // bootstrap admin + seed roles/permissions
	router, err := NewRouter(&config.Config{}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return c, srv.URL
}

// g3CreateProjectB creates a SECOND project, distinct from the bootstrap
// project (projectA in every probe below) -- the "target the caller has
// nothing in" half of the cross-project probes.
func g3CreateProjectB(t *testing.T, c *core.KeyorixCore) uint {
	t.Helper()
	p, err := c.CreateProject(context.Background(), "g3-probe-project-b", "probe fixture, unrelated to projectA")
	require.NoError(t, err)
	return p.ID
}

// g3CreateScopedRolesAssignToken mints a human user holding system.write at
// GLOBAL scope (required just to reach the /system route group at all --
// RequirePermission == RequireScopedPermission(_, ScopeGlobal)) and
// roles.assign scoped ONLY to atProjectID -- never global, never at any
// other project. Two separate roles are used because a single role's grant
// can only be assigned at one scope; bundling both permissions into one role
// would force them to share atProjectID's scope, which would also strip the
// caller's ability to reach the /system group (system.write would then be
// project-scoped, not global).
func g3CreateScopedRolesAssignToken(t *testing.T, c *core.KeyorixCore, atProjectID uint, tag string) (token string, userID uint) {
	t.Helper()
	ctx := context.Background()
	username := "g3_probe_" + tag
	email := username + "@example.com"
	_, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: username, Email: email, Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, email, "system_viewer"))

	perms, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID, rolesAssignID uint
	for _, p := range perms {
		switch p.Name {
		case "system.write":
			systemWriteID = p.ID
		case "roles.assign":
			rolesAssignID = p.ID
		}
	}
	require.NotZero(t, systemWriteID, "system.write permission must already be seeded by bootstrap")
	require.NotZero(t, rolesAssignID, "roles.assign permission must already be seeded by bootstrap")

	swRoleName, err := identity.NewFoldedName("g3_probe_sw_role_" + tag)
	require.NoError(t, err)
	swRole, err := c.Storage().CreateRole(ctx, swRoleName, "test-only: system.write, global scope")
	require.NoError(t, err)
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, swRole.ID, systemWriteID, false))
	require.NoError(t, c.AssignUserRoleScoped(ctx, email, swRoleName.String(), core.Scope{}))

	raRoleName, err := identity.NewFoldedName("g3_probe_ra_role_" + tag)
	require.NoError(t, err)
	raRole, err := c.Storage().CreateRole(ctx, raRoleName, "test-only: roles.assign, scoped to ONE project only")
	require.NoError(t, err)
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, raRole.ID, rolesAssignID, false))
	require.NoError(t, c.AssignUserRoleScoped(ctx, email, raRoleName.String(), core.Scope{ProjectID: atProjectID}))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: username, Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	u, err := c.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	return sess.SessionToken, u.ID
}

func g3Do(t *testing.T, serverURL, token, method, path string, body any) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, serverURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

func g3ContainsUserID(users []*models.User, id uint) bool {
	for _, u := range users {
		if u.ID == id {
			return true
		}
	}
	return false
}

// --- 1. AddGroupMemberProxy -------------------------------------------------

func TestG3Probe_AddGroupMemberProxy_SystemWriteOnly_AddsMemberToOrdinaryGroup(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()

	group, err := c.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "g3-probe-ordinary-group", Description: "holds no role at all"})
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "g3_probe_group_target", Email: "g3_probe_group_target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)

	token := createSystemWriteOnlyToken(t, c)

	before, err := c.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)

	status, body := g3Do(t, serverURL, token, http.MethodPost, fmt.Sprintf("/api/v1/system/groups/%d/members", group.ID), map[string]any{"user_id": target.ID})

	after, err := c.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)

	t.Logf("AddGroupMemberProxy probe: principal=system.write-only (no roles.assign anywhere); request=POST /groups/%d/members {user_id:%d}; status=%d body=%s; members before=%d after=%d",
		group.ID, target.ID, status, body, len(before), len(after))
	require.Equal(t, http.StatusForbidden, status, "a system.write-only caller with no roles.assign must be refused")
	require.Len(t, after, len(before), "CEILING VIOLATED: group membership changed with zero authority")
}

// --- 2. RemoveGroupMemberProxy ----------------------------------------------

func TestG3Probe_RemoveGroupMemberProxy_SystemWriteOnly_RemovesMemberFromOrdinaryGroup(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()

	group, err := c.CreateGroup(ctx, 0, &core.CreateGroupRequest{Name: "g3-probe-removal-group"})
	require.NoError(t, err)
	member, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "g3_probe_removal_member", Email: "g3_probe_removal_member@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	require.NoError(t, c.AddUserToGroup(ctx, 0, false, member.ID, group.ID, 0))

	token := createSystemWriteOnlyToken(t, c)

	before, err := c.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	beforePresent := g3ContainsUserID(before, member.ID)
	require.True(t, beforePresent, "fixture setup must actually seed the membership")

	status, body := g3Do(t, serverURL, token, http.MethodDelete, fmt.Sprintf("/api/v1/system/groups/%d/members/%d", group.ID, member.ID), nil)

	after, err := c.Storage().ListGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	afterPresent := g3ContainsUserID(after, member.ID)

	t.Logf("RemoveGroupMemberProxy probe: principal=system.write-only (no roles.assign anywhere); request=DELETE /groups/%d/members/%d; status=%d body=%s; member present before=%v after=%v",
		group.ID, member.ID, status, body, beforePresent, afterPresent)
	require.Equal(t, http.StatusForbidden, status, "a system.write-only caller with no roles.assign must be refused")
	require.True(t, afterPresent, "CEILING VIOLATED: group membership was revoked with zero authority")
}

// --- 3. CreateInvitationProxy ------------------------------------------------

func TestG3Probe_CreateInvitationProxy_SystemWriteOnly_CreatesRoleLessInvitation(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID

	token := createSystemWriteOnlyToken(t, c)

	before, err := c.Storage().ListProjectInvitations(ctx, projectID)
	require.NoError(t, err)

	// Deliberately NO role/system_role/assignments_json -- the wire shape that
	// skips every RequireGranterHoldsRolePermissions check the allowlist
	// reasoning describes (all three are gated on a non-empty field).
	status, body := g3Do(t, serverURL, token, http.MethodPost, "/api/v1/system/invitations", map[string]any{
		"project_id": projectID, "email": "g3-probe-roleless-invite@example.invalid", "state": "pending",
	})

	after, err := c.Storage().ListProjectInvitations(ctx, projectID)
	require.NoError(t, err)

	t.Logf("CreateInvitationProxy probe: principal=system.write-only (no roles.assign anywhere); request=POST /invitations {project_id:%d,email:...,state:pending, NO role/system_role/assignments_json}; status=%d body=%s; invitations before=%d after=%d",
		projectID, status, body, len(before), len(after))
	require.Equal(t, http.StatusForbidden, status, "a system.write-only caller with no roles.assign must be refused")
	require.Len(t, after, len(before), "CEILING VIOLATED: a role-less invitation was created with zero authority")
}

// --- 4/5. UpdateAccessRequestProxy / CreateAccessRequestApprovalProxy ------

// g3SeedEmptyRoleAccessRequest creates a role that bundles ZERO permissions
// (isolating the missing roles.assign baseline from RequireGranterHoldsRolePermissions,
// which is vacuous for such a role) and a pending, SecretID-nil access
// request in projectB suggesting that role.
func g3SeedEmptyRoleAccessRequest(t *testing.T, c *core.KeyorixCore, projectB uint, tag string) *models.AccessRequest {
	t.Helper()
	ctx := context.Background()
	emptyRoleName, err := identity.NewFoldedName("g3_probe_empty_role_" + tag)
	require.NoError(t, err)
	_, err = c.Storage().CreateRole(ctx, emptyRoleName, "test-only: bundles zero permissions")
	require.NoError(t, err)

	requester, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "g3_probe_ar_requester_" + tag, Email: "g3_probe_ar_requester_" + tag + "@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)

	created, err := c.Storage().CreateAccessRequest(ctx, &models.AccessRequest{
		ProjectID: projectB, UserID: requester.ID, SuggestedRole: emptyRoleName.String(), State: core.AccessRequestPending,
	})
	require.NoError(t, err)
	return created
}

func TestG3Probe_UpdateAccessRequestProxy_RolesAssignOnOtherProject_ApprovesRequestInWrongProject(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectA := projects[0].ID
	projectB := g3CreateProjectB(t, c)

	created := g3SeedEmptyRoleAccessRequest(t, c, projectB, "update")
	token, _ := g3CreateScopedRolesAssignToken(t, c, projectA, "ar_update")

	status, body := g3Do(t, serverURL, token, http.MethodPut, fmt.Sprintf("/api/v1/system/access-requests/%d", created.ID), map[string]any{
		"state": "approved",
	})

	after, err := c.Storage().GetAccessRequest(ctx, created.ID)
	require.NoError(t, err)

	t.Logf("UpdateAccessRequestProxy probe: principal holds roles.assign@projectA=%d ONLY; target access-request %d is in projectB=%d (suggested role bundles zero permissions); request=PUT approve; status=%d body=%s; state before=pending after=%q",
		projectA, created.ID, projectB, status, body, after.State)
	require.Equal(t, http.StatusForbidden, status, "a caller with roles.assign only on a DIFFERENT project must be refused")
	require.Equal(t, core.AccessRequestPending, after.State, "CEILING VIOLATED: request approved by a caller with no authority on its real project")
}

func TestG3Probe_CreateAccessRequestApprovalProxy_RolesAssignOnOtherProject_RecordsApprovalInWrongProject(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectA := projects[0].ID
	projectB := g3CreateProjectB(t, c)

	created := g3SeedEmptyRoleAccessRequest(t, c, projectB, "approval")
	token, _ := g3CreateScopedRolesAssignToken(t, c, projectA, "ar_approval")

	before, err := c.Storage().ListAccessRequestApprovals(ctx, created.ID)
	require.NoError(t, err)

	status, body := g3Do(t, serverURL, token, http.MethodPost, fmt.Sprintf("/api/v1/system/access-requests/%d/approvals", created.ID), map[string]any{})

	after, err := c.Storage().ListAccessRequestApprovals(ctx, created.ID)
	require.NoError(t, err)

	t.Logf("CreateAccessRequestApprovalProxy probe: principal holds roles.assign@projectA=%d ONLY; target access-request %d is in projectB=%d (suggested role bundles zero permissions); status=%d body=%s; approvals before=%d after=%d",
		projectA, created.ID, projectB, status, body, len(before), len(after))
	require.Equal(t, http.StatusForbidden, status, "a caller with roles.assign only on a DIFFERENT project must be refused")
	require.Len(t, after, len(before), "CEILING VIOLATED: an approval was recorded by a caller with no authority on the request's real project")
}

// --- 6. CreateMembershipProxy ------------------------------------------------

func TestG3Probe_CreateMembershipProxy_RolesAssignOnOtherProject_CreatesMembershipViaEmptyPermissionRole(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectA := projects[0].ID
	projectB := g3CreateProjectB(t, c)

	emptyRoleName, err := identity.NewFoldedName("g3_probe_empty_role_membership")
	require.NoError(t, err)
	_, err = c.Storage().CreateRole(ctx, emptyRoleName, "test-only: bundles zero permissions")
	require.NoError(t, err)

	target, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "g3_probe_membership_target", Email: "g3_probe_membership_target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)

	token, _ := g3CreateScopedRolesAssignToken(t, c, projectA, "membership_create")

	before, err := c.Storage().ListProjectMemberships(ctx, projectB)
	require.NoError(t, err)

	status, body := g3Do(t, serverURL, token, http.MethodPost, "/api/v1/system/project-memberships", map[string]any{
		"project_id": projectB, "user_id": target.ID, "role": emptyRoleName.String(), "state": "active",
	})

	after, err := c.Storage().ListProjectMemberships(ctx, projectB)
	require.NoError(t, err)

	t.Logf("CreateMembershipProxy probe: principal holds roles.assign@projectA=%d ONLY; target project B=%d, role bundles zero permissions; status=%d body=%s; memberships before=%d after=%d",
		projectA, projectB, status, body, len(before), len(after))
	require.Equal(t, http.StatusForbidden, status, "a caller with roles.assign only on a DIFFERENT project must be refused")
	require.Len(t, after, len(before), "CEILING VIOLATED: an active project membership was created in a project the caller has no authority on")
}

// --- 7/8. TransitionMembershipProxy -----------------------------------------

func TestG3Probe_TransitionMembershipProxy_RolesAssignOnOtherProject_RevokesActiveMembershipInWrongProject(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectA := projects[0].ID
	projectB := g3CreateProjectB(t, c)

	target, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "g3_probe_transition_target", Email: "g3_probe_transition_target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	m, err := c.Storage().CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: projectB, UserID: target.ID, Role: "project_viewer", State: core.MembershipActive})
	require.NoError(t, err)

	token, _ := g3CreateScopedRolesAssignToken(t, c, projectA, "transition_correct_pid")

	// The wire body supplies the CORRECT project_id (B) -- the caller isn't
	// lying about it, they just don't hold roles.assign there.
	status, body := g3Do(t, serverURL, token, http.MethodPut, fmt.Sprintf("/api/v1/system/project-memberships/%d/transition", m.ID), map[string]any{
		"membership": map[string]any{"id": m.ID, "project_id": projectB, "state": "revoked"},
		"from_state": "active",
	})

	after, err := c.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)

	t.Logf("TransitionMembershipProxy probe (correct project_id): principal holds roles.assign@projectA=%d ONLY; membership %d is ACTIVE in projectB=%d; request supplies the CORRECT project_id=%d, transition to revoked; status=%d body=%s; state before=active after=%q",
		projectA, m.ID, projectB, projectB, status, body, after.State)
	require.Equal(t, http.StatusForbidden, status, "a caller with roles.assign only on a DIFFERENT project must be refused")
	require.Equal(t, core.MembershipActive, after.State, "CEILING VIOLATED: an active membership was revoked by a caller with zero authority on its real project")
}

// TestG3Probe_TransitionMembershipProxy_SpoofedProjectID_RefusedByCrossProjectGuard
// is a CONTROL, not a gap probe: it exercises the specific attack shape the
// earlier read-only pass likely had in mind when it marked this route
// "fixed (#1546)" -- lying about project_id to redirect the wire-supplied
// authority check onto a project the row doesn't actually belong to.
// core.TransitionMembership's own `m.ProjectID != projectID` guard (an
// ID-consistency check, not an authority check) DOES catch this shape. The
// probe above proves that guard is a DIFFERENT thing from an authority
// ceiling: supplying the CORRECT project_id sails through with zero
// authority for every non-Active transition.
func TestG3Probe_TransitionMembershipProxy_SpoofedProjectID_RefusedByCrossProjectGuard(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	projects, err := c.Storage().ListProjects(ctx)
	require.NoError(t, err)
	projectA := projects[0].ID
	projectB := g3CreateProjectB(t, c)

	target, err := c.CreateUser(ctx, &core.CreateUserRequest{Username: "g3_probe_transition_spoof_target", Email: "g3_probe_transition_spoof_target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	m, err := c.Storage().CreateProjectMembership(ctx, &models.ProjectMembership{ProjectID: projectB, UserID: target.ID, Role: "project_viewer", State: core.MembershipActive})
	require.NoError(t, err)

	token, _ := g3CreateScopedRolesAssignToken(t, c, projectA, "transition_spoofed_pid")

	// The caller lies: claims project_id=A (their OWN authorized project) for
	// a membership that actually lives in B.
	status, body := g3Do(t, serverURL, token, http.MethodPut, fmt.Sprintf("/api/v1/system/project-memberships/%d/transition", m.ID), map[string]any{
		"membership": map[string]any{"id": m.ID, "project_id": projectA, "state": "revoked"},
		"from_state": "active",
	})

	after, err := c.Storage().GetProjectMembership(ctx, m.ID)
	require.NoError(t, err)

	t.Logf("TransitionMembershipProxy probe (SPOOFED project_id, control): principal holds roles.assign@projectA=%d; membership %d actually lives in projectB=%d but the wire body claims project_id=%d (the caller's OWN project); status=%d body=%s; state after=%q",
		projectA, m.ID, projectB, projectA, status, body, after.State)
	require.NotEqual(t, http.StatusOK, status, "core.TransitionMembership's cross-project guard (m.ProjectID != projectID) should refuse a mismatched project_id")
	require.Equal(t, core.MembershipActive, after.State, "the row must be untouched when the wire project_id doesn't match its real project")
}

// --- 9. CreateUserWithRoleGrantsProxy ---------------------------------------

func TestG3Probe_CreateUserWithRoleGrantsProxy_SystemWriteOnly_CreatesUserWithEmptyGrants(t *testing.T) {
	c, serverURL := setupG3ProbeServer(t)
	ctx := context.Background()
	token := createSystemWriteOnlyToken(t, c)

	const email = "g3-probe-free-account@example.invalid"
	_, errBefore := c.Storage().GetUserByEmail(ctx, email)
	require.Error(t, errBefore, "target account must not exist yet")

	fakeHash := "$2a$10$" + strings.Repeat("N", 53) // 60 chars total, isPlausibleBcryptHash-shaped
	status, body := g3Do(t, serverURL, token, http.MethodPost, "/api/v1/system/users/with-role-grants", map[string]any{
		"username": "g3-probe-free-account", "email": email, "password_hash": fakeHash,
		"is_active": true, "account_state": "active", "grants": []any{},
	})

	_, errAfter := c.Storage().GetUserByEmail(ctx, email)

	t.Logf("CreateUserWithRoleGrantsProxy probe: principal=system.write-only (no users.write anywhere), grants=[]; status=%d body=%s; user existed before=%v exists after=%v",
		status, body, errBefore == nil, errAfter == nil)
	require.Equal(t, http.StatusForbidden, status, "a system.write-only caller with no users.write must be refused")
	require.Error(t, errAfter, "CEILING VIOLATED: a brand-new, fully-active user account was minted with zero authority")
}
