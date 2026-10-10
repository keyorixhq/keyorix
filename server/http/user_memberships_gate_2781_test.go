// user_memberships_gate_2781_test.go — PROJ-ACCESS-1 option B: pin the REAL gate on
// GET /api/v1/users/{id}/memberships, through the router.
//
// # Why this file exists
//
// #2856's own doc comment flagged a residual: that route's fix changes the response
// from "always []" to "the target's project-scoped grants, with project id and name",
// and I claimed a CUSTOM role holding global roles.read but NOT users.read would
// therefore see something new. Andrei approved closing that if it was open.
//
// It is NOT open, and this file is the proof plus the guard. The gate is two layers,
// not one:
//
//	router.go's /users group:  r.Use(RequirePermission(permUsersRead))
//	                           -> GLOBAL users.read, every route in the group
//	the handler (users_roles.go): canReadRBACStateFor
//	                           -> self OR GLOBAL roles.read
//
// so the effective rule is **global users.read AND (self OR global roles.read)**.
// A caller with roles.read and no users.read is refused by the ROUTE and never
// reaches the handler at all. `RequirePermission(p)` is `RequireScopedPermission(p,
// ScopeGlobal)` (server/middleware/auth.go), so "users.read" there means global
// users.read — a project-scoped users.read grant does not satisfy it.
//
// # This has to be a router-level test
//
// The outer layer is route MIDDLEWARE. A handler-level test calls
// GetUserMembershipsForUser directly, so it cannot see the route gate at all and
// would stay green if that `r.Use` were deleted — the same asymmetry #2780's
// project-listing fix ran into (see project_listing_least_privilege_2780_test.go's
// header, and the red/green proof in that PR). So this drives the real NewRouter
// with real session tokens over real HTTP.
//
// # Both layers are asserted load-bearing, in both directions
//
// Asserting only the coordinator's case (roles.read without users.read -> 403) would
// not distinguish "the route gate refuses it" from "everything refuses everything":
// a test that only ever expects 403 passes just as well against a route that is
// broken for everyone. So each layer gets a case where it is the ONLY thing
// refusing, plus a positive control that the combination really does return 200.
package http

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
)

const membershipsGatePassword = "CorrectHorse9Battery!"

// uid renders a user ID for a URL. Spelled out rather than reusing this package's
// itoa(int), which would need a uint->int conversion gosec flags (G115).
func uid(id uint) string { return strconv.FormatUint(uint64(id), 10) }

// mkRoleWithPermissions creates a role carrying exactly the named permissions,
// resolved from the ones bootstrap seeded (so a typo fails loudly here rather than
// silently producing a role with fewer permissions than the test assumes).
func mkRoleWithPermissions(t *testing.T, cs *core.KeyorixCore, roleName string, want ...string) {
	t.Helper()
	ctx := context.Background()
	perms, err := cs.ListPermissions(ctx)
	require.NoError(t, err)
	byName := map[string]uint{}
	for _, p := range perms {
		byName[p.Name] = p.ID
	}
	ids := make([]uint, 0, len(want))
	for _, n := range want {
		id, ok := byName[n]
		require.Truef(t, ok, "permission %q must exist after bootstrap", n)
		ids = append(ids, id)
	}
	admin, err := cs.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	_, _, err = cs.CreateRole(ctx, admin.ID, roleName, "PROJ-ACCESS-1 gate fixture: "+roleName, ids)
	require.NoError(t, err)
}

// mkUserWithGlobalRole creates a user, grants roleName at GLOBAL scope, logs them
// in, and returns (userID, sessionToken).
func mkUserWithGlobalRole(t *testing.T, cs *core.KeyorixCore, username, roleName string) (uint, string) {
	t.Helper()
	ctx := context.Background()
	email := username + "@example.com"
	u, err := cs.CreateUser(ctx, &core.CreateUserRequest{
		Username: username, Email: email, DisplayName: username, Password: membershipsGatePassword,
	})
	require.NoError(t, err)
	if roleName != "" {
		require.NoError(t, cs.AssignRoleToUser(ctx, email, roleName))
	}
	sess, _, err := cs.Login(ctx, &core.LoginRequest{Username: username, Password: membershipsGatePassword})
	require.NoError(t, err)
	return u.ID, sess.SessionToken
}

func TestUserMemberships2781_GateIsGlobalUsersReadAndSelfOrRolesRead(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	adminToken := createTestToken(t, testCore) // bootstraps roles + permissions
	ctx := context.Background()

	// A real membership to disclose, so a 200 has something in it and the 403 cases
	// are refusing access to actual data rather than to an empty list.
	project, err := testCore.CreateProject(ctx, "p2781gate-payments", "gate fixture")
	require.NoError(t, err)

	mkRoleWithPermissions(t, testCore, "p2781gate_roles_only", "roles.read")
	mkRoleWithPermissions(t, testCore, "p2781gate_users_only", "users.read")
	mkRoleWithPermissions(t, testCore, "p2781gate_both", "users.read", "roles.read")

	// The TARGET: a user who really is a member of the project, so every refusal
	// below is withholding something real.
	targetID, _ := mkUserWithGlobalRole(t, testCore, "p2781gatetarget", "")
	require.NoError(t, testCore.AddProjectMember(ctx, 1, project.ID, targetID, "project_viewer", false))

	_, rolesOnlyToken := mkUserWithGlobalRole(t, testCore, "p2781gaterolesonly", "p2781gate_roles_only")
	_, usersOnlyToken := mkUserWithGlobalRole(t, testCore, "p2781gateusersonly", "p2781gate_users_only")
	_, bothToken := mkUserWithGlobalRole(t, testCore, "p2781gateboth", "p2781gate_both")

	client := &http.Client{Timeout: 10 * time.Second}
	get := func(t *testing.T, token, path string) (int, []byte) {
		t.Helper()
		req, rerr := http.NewRequest(http.MethodGet, server.URL+path, nil)
		require.NoError(t, rerr)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, derr := client.Do(req)
		require.NoError(t, derr)
		defer func() { _ = resp.Body.Close() }()
		body, berr := io.ReadAll(resp.Body)
		require.NoError(t, berr)
		return resp.StatusCode, body
	}
	membershipsPath := func(id uint) string {
		return "/api/v1/users/" + uid(id) + "/memberships"
	}
	countRows := func(t *testing.T, body []byte) int {
		t.Helper()
		var env struct {
			Data struct {
				Memberships []map[string]any `json:"memberships"`
			} `json:"data"`
		}
		require.NoError(t, json.Unmarshal(body, &env), "body: %s", body)
		return len(env.Data.Memberships)
	}

	// The positive control FIRST: if this does not return a real row, every 403
	// below could be a broken route rather than a working gate.
	t.Run("positive_control_users_read_and_roles_read_sees_the_membership", func(t *testing.T) {
		code, body := get(t, bothToken, membershipsPath(targetID))
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Equal(t, 1, countRows(t, body),
			"the combination must actually disclose the membership — otherwise the refusals below prove nothing")
	})

	// The case Andrei asked about. Refused by the ROUTE, before the handler runs.
	t.Run("roles_read_without_users_read_is_refused", func(t *testing.T) {
		code, _ := get(t, rolesOnlyToken, membershipsPath(targetID))
		assert.Equal(t, http.StatusForbidden, code,
			"the /users route group requires GLOBAL users.read, so a roles.read-only caller never reaches "+
				"GetUserMembershipsForUser — this is what closes #2856's flagged residual")
	})

	// The complementary case, so the handler's own arm is shown load-bearing too.
	// Without this, deleting canReadRBACStateFor would leave the file green.
	t.Run("users_read_without_roles_read_is_refused", func(t *testing.T) {
		code, _ := get(t, usersOnlyToken, membershipsPath(targetID))
		assert.Equal(t, http.StatusForbidden, code,
			"clearing the route gate is not enough: the handler still requires self OR global roles.read (G84)")
	})

	// Self-read: the handler's other arm. It still needs the route's global
	// users.read, which is why this persona is given it.
	t.Run("self_read_with_users_read_is_allowed", func(t *testing.T) {
		selfID, selfToken := mkUserWithGlobalRole(t, testCore, "p2781gateself", "p2781gate_users_only")
		code, body := get(t, selfToken, membershipsPath(selfID))
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Equal(t, 0, countRows(t, body), "this user is a member of nothing, and is told so")
	})

	// An admin is unaffected by both layers.
	t.Run("admin_is_unaffected", func(t *testing.T) {
		code, body := get(t, adminToken, membershipsPath(targetID))
		require.Equal(t, http.StatusOK, code, "body: %s", body)
		assert.Equal(t, 1, countRows(t, body))
	})
}

// TestUserMemberships2781_ProjectScopedUserCannotReadEvenTheirOwn records a
// consequence of the route gate that is worth pinning rather than discovering again:
// the handler's `self` arm cannot serve a project-scoped user AT ALL.
//
// `project_viewer` bundles users.read, but a project-scoped grant does not satisfy
// `RequirePermission(permUsersRead)` (global). So the WEB-SWEEP-1 persona —
// system_viewer globally + project_viewer on one project — gets 403 on their OWN
// memberships. The self arm only ever fires for a caller who already holds global
// users.read (viewer/editor/system_auditor/admin).
//
// This is fail-closed and currently harmless: the web UI only calls this endpoint
// from the admin-only /admin/users/:id page, never for a self-read. It is asserted
// here, not changed, for two reasons — widening the route gate to admit a
// project-scoped users.read would WEAKEN a security default for every other route in
// the /users group, and the alternative (exempting self from the group gate) is a
// product decision, not a drive-by. If the UI ever grows a "my project assignments"
// view on /profile, this test is the thing that will fail and point at the decision.
func TestUserMemberships2781_ProjectScopedUserCannotReadEvenTheirOwn(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	testCore := newFullSchemaTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	_ = createTestToken(t, testCore)
	ctx := context.Background()

	project, err := testCore.CreateProject(ctx, "p2781gate-scoped", "gate fixture")
	require.NoError(t, err)

	// Exactly WEB-SWEEP-1's persona, built through the product's own API.
	_, err = testCore.CreateUserWithAssignments(ctx, &core.CreateUserRequest{
		Username: "p2781gatescoped", Email: "p2781gatescoped@example.com", Password: membershipsGatePassword,
	}, "system_viewer", []core.ProjectAssignment{{ProjectID: project.ID, Role: "project_viewer"}}, 0, false)
	require.NoError(t, err)
	sess, _, err := testCore.Login(ctx, &core.LoginRequest{
		Username: "p2781gatescoped", Password: membershipsGatePassword,
	})
	require.NoError(t, err)
	self, err := testCore.GetUserByEmail(ctx, "p2781gatescoped@example.com")
	require.NoError(t, err)

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/api/v1/users/"+uid(self.ID)+"/memberships", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+sess.SessionToken)
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"project_viewer's users.read is PROJECT-scoped and the /users group requires it GLOBALLY, so this "+
			"persona cannot read even their own memberships. Fail-closed and unreachable from today's UI "+
			"(the endpoint is only called from the admin-only user-detail page); asserted so the constraint "+
			"is explicit rather than rediscovered")

	// And the membership really does exist — so the 403 above is withholding
	// something, not reporting an empty truth.
	rows, err := testCore.ListProjectMembershipsForUser(ctx, self.ID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "the persona IS a member of the project; the 403 is a refusal, not an empty result")
}
