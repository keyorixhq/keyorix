// system_write_ceiling_walk_test.go replaces system_write_ceiling_table_test.go
// and system_write_ceiling_table_users_test.go (which covered only the
// machine-identities/credentials/oidc-bindings group and the two
// users-credentials routes) with a single chi.Walk over the ENTIRE
// /api/v1/system route tree: F6 of the system-proxy-target-authority audit.
//
// Every mutating (POST/PUT/DELETE/PATCH) route under /api/v1/system is
// walked from the real, registered router. For each route:
//   - if it's in systemCeilingReadOnly: it's a read despite its HTTP method
//     (e.g. GetActiveMFAStepUpGrantProxy is a POST-with-body read) — skipped,
//     not part of the mutating population at all.
//   - if it's in systemCeilingAllowlist: system.write alone is the reviewed,
//     sufficient ceiling — skipped, with a one-line reason recorded in the
//     map (not a comment that could rot silently).
//   - otherwise it MUST be in systemCeilingDenyChecked, meaning a dedicated
//     Test* function elsewhere in this file already sends a request as
//     f.token (system.write-only, zero other permission) and asserts it is
//     refused. The walk does not re-send that request (many of these need
//     specific fixture IDs/bodies the walk's generic loop can't derive); it
//     only asserts EVERY discovered route has such a row somewhere.
//   - a route in none of the three fails the walk outright: "add a row."
//     That failure IS the ratchet — a new /system route can't silently ship
//     unreviewed.
//
// F5 and every gap this same audit found (SecretDependency, TransitionSecretStatus,
// Groups create/update/delete/restore, ExpireSetupToken, UpdateWebAuthnCredential,
// UpdateInvitation) are listed in systemCeilingDenyChecked identically to
// every already-fixed row — no "known-open" marker, no comment naming which
// ones are currently exploitable. Before their fix commits land, their rows
// are simply red; that failure output is this branch's red-proof, not a
// vulnerability disclosure sitting in committed test code.
//
// The existing zero-role walk (integration_test.go's TestMutatingRoutesRequireAuth
// or equivalent) is unrelated and untouched: it proves a caller with NO role at
// all can never succeed at a mutation anywhere in the API. This walk proves a
// narrower, different thing: that holding ONLY the /system group's own blanket
// system.write permission is never enough, on its own, to reach a route whose
// real ceiling is something else.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── Fixtures ─────────────────────────────────────────────────────────────────

// systemCeilingFixtures is the union of the two replaced files' fixture
// structs, plus the additional rows the seven new fix routes need. Built
// once per test (each Test* function calls setupSystemCeilingFixtures
// itself — no cross-test sharing, matching the replaced files' own
// isolation).
type systemCeilingFixtures struct {
	serverURL string
	token     string // dimension (a): human, system.write only

	// Dimensions (b)/(c): the 3-principal model (system-proxy-target-authority
	// audit, user-directed extension of F6). nodeToken holds ZERO role grants
	// -- must be refused at the /system group's own gate on every mutating
	// route (ADR-085). permissionedNodeToken holds ONLY system.write, via
	// createSystemWriteOnlyNodeToken below -- NOT createNodeToken
	// (integration_test.go), which assigns the full "admin" role
	// (adminRoleNames, authz.go) and so bypasses every check unconditionally,
	// making it useless as a narrow-permission principal. usersWriteNodeToken/
	// rolesAssignNodeToken are the machine-actor analogues of usersWriteToken/
	// rolesAssignToken below, for the 5 real-caller routes' positive controls
	// (Task 3): CLI client mode authenticates with an operator-provisioned
	// bearer token of EITHER actor type (internal/cli/modes.go's
	// initClientMode reads a plain configured API key, not a fixed role or
	// actor type) -- core.AuthorizePrincipal's machine branch
	// (GetMachineRoleIDsAt + RoleSetHasPermission) is a materially different
	// code path from the human branch (c.Authorize), so a human-only positive
	// control does not cover a real machine-credential deployment.
	nodeToken             string
	permissionedNodeToken string
	usersWriteNodeToken   string
	rolesAssignNodeToken  string

	rolesAssignToken  string // system.write + roles.assign human caller
	usersWriteToken   string // system.write + users.write human caller
	projectID         uint
	envID             uint
	plainMachine      uint
	adminMachine      uint
	revokedMach       uint
	plainCredID       uint
	revokedCredID     uint
	bindingID         uint
	normalRoleID      uint
	adminRoleID       uint
	secondAdminUserID uint
	setupTargetUserID uint

	// New for the seven-item fix set.
	regularUserID          uint // a plain user, no roles, target for groups/webauthn/invitation rows
	dependentSecretID      uint // secretA: the "dependent" endpoint of a dependency edge
	dependsOnSecretID      uint // secretB: the "depends_on" endpoint -- f.token has NO secrets.write on it
	activeSecretID         uint // a third, ACTIVE secret -- suspend-direction target
	suspendedSecretID      uint // a fourth secret, already SUSPENDED before the test runs -- resume-direction target
	nonAdminGroupID        uint // an existing group holding a non-admin role, for update/delete/restore rows
	adminTierGroupID       uint // a group holding system_admin, for the AddGroupMemberProxy deny row
	deletedGroupID         uint // a soft-deleted group holding a non-admin role, for the restore row
	setupTokenID           uint // an existing, unexpired setup token, for the expire row
	webauthnCredentialID   uint // a real WebAuthn credential belonging to regularUserID
	pendingInvitationID    uint // a pending project invitation, for the update-invitation row
	breakGlassActivationID uint // an active break-glass activation, for the revoke row
	accessReviewCampaignID uint // an open access-review campaign
	accessReviewItemID     uint // a pending item on that campaign, principal != caller
}

func setupSystemCeilingFixtures(t *testing.T) systemCeilingFixtures {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	ctx := context.Background()
	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projectID := projects[0].ID
	envs, err := testCore.Storage().ListEnvironmentsByProject(ctx, projectID)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	envID := envs[0].ID

	plainMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-walk-plain", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)

	adminMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-walk-admin-tier", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)
	adminRole, err := testCore.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	require.NoError(t, testCore.AssignMachineRole(ctx, adminMachine.ID, adminRole.ID, core.Scope{ProjectID: projectID}, admin.ID, false))

	revokedMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-walk-revoked", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)
	revokedMachine.State = core.MachineRevoked
	matched, err := testCore.Storage().TransitionMachineIdentityState(ctx, revokedMachine, core.MachineActive)
	require.NoError(t, err)
	require.True(t, matched)

	plainCred, err := testCore.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: plainMachine.ID, Name: "plain-cred", TokenHash: "aaaa000000000000000000000000000000000000000000000000000000000001", TokenPrefix: "mid_a",
	})
	require.NoError(t, err)

	revokedCred, err := testCore.Storage().CreateMachineIdentityCredential(ctx, &models.MachineIdentityCredential{
		MachineIdentityID: plainMachine.ID, Name: "revoked-cred", TokenHash: "bbbb000000000000000000000000000000000000000000000000000000000002", TokenPrefix: "mid_b", Revoked: true,
	})
	require.NoError(t, err)

	binding, err := testCore.Storage().CreateOIDCBinding(ctx, &models.MachineIdentityOIDCBinding{
		MachineIdentityID: plainMachine.ID, Issuer: "https://ceiling-walk.example", Subject: "walk-subject", CreatedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	ceilingWalkNormalRoleName, err := identity.NewFoldedName("ceiling_walk_normal_role")
	require.NoError(t, err)
	normalRole, err := testCore.Storage().CreateRole(ctx, ceilingWalkNormalRoleName, "non-admin")
	require.NoError(t, err)

	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ceiling-walk-second-admin", Email: "ceiling-walk-second-admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, testCore.AssignRoleToUser(ctx, "ceiling-walk-second-admin@example.com", "system_admin"))
	secondAdmin, err := testCore.GetUserByEmail(ctx, "ceiling-walk-second-admin@example.com")
	require.NoError(t, err)

	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ceiling-walk-setup-target", Email: "ceiling-walk-setup-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	setupTarget, err := testCore.GetUserByEmail(ctx, "ceiling-walk-setup-target@example.com")
	require.NoError(t, err)

	regularUser, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ceiling-walk-regular", Email: "ceiling-walk-regular@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, testCore.RemoveRoleFromUser(ctx, "ceiling-walk-regular@example.com", "system_viewer"))

	token := createSystemWriteOnlyToken(t, testCore)
	nodeToken := createBareNodeToken(t, testCore)
	rolesAssignToken := createSystemWriteAndRolesAssignToken(t, testCore)
	usersWriteToken := createSystemWriteAndUsersWriteToken(t, testCore)
	// The three node-credential fixtures below reuse the ROLE NAMES the three
	// human tokens above just created (role names are unique per-install, not
	// per-actor) -- must run after the human token calls, which seed those
	// roles.
	permissionedNodeToken := createSystemWriteOnlyNodeToken(t, testCore)
	usersWriteNodeToken := createUsersWriteNodeToken(t, testCore)
	rolesAssignNodeToken := createRolesAssignNodeToken(t, testCore)

	// Two secrets in the SAME project+environment, for the secret-dependency row:
	// f.token (system.write only) has no secrets.write ACL on either.
	dependent, err := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "ceiling-walk-dependent", Value: []byte("v1"), ProjectID: projectID, EnvironmentID: envID,
		Type: "password", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)
	dependsOn, err := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "ceiling-walk-dependson", Value: []byte("v2"), ProjectID: projectID, EnvironmentID: envID,
		Type: "password", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)

	activeSecret, err := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "ceiling-walk-active-secret", Value: []byte("v3"), ProjectID: projectID, EnvironmentID: envID,
		Type: "password", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)

	suspendedSecret, err := testCore.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "ceiling-walk-suspended-secret", Value: []byte("v4"), ProjectID: projectID, EnvironmentID: envID,
		Type: "password", OwnerID: admin.ID, CreatedBy: "admin",
	})
	require.NoError(t, err)
	_, err = testCore.SuspendSecret(ctx, suspendedSecret.ID, admin.ID, "ceiling-walk fixture setup")
	require.NoError(t, err)

	// A group holding a NON-admin role, plus a soft-deleted twin (also
	// non-admin) for the restore row.
	nonAdminGroup, err := testCore.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "ceiling-walk-group", Description: "non-admin"})
	require.NoError(t, err)

	adminTierGroup, err := testCore.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "ceiling-walk-admin-tier-group", Description: "holds system_admin"})
	require.NoError(t, err)
	require.NoError(t, testCore.AssignGroupRoleWithExpiry(ctx, admin.ID, adminTierGroup.ID, adminRole.ID, core.Scope{}, time.Now().Add(24*time.Hour), false))

	deletedGroup, err := testCore.CreateGroup(ctx, admin.ID, &core.CreateGroupRequest{Name: "ceiling-walk-deleted-group", Description: "non-admin, soft-deleted"})
	require.NoError(t, err)
	require.NoError(t, testCore.AssignGroupRoleWithExpiry(ctx, admin.ID, deletedGroup.ID, normalRole.ID, core.Scope{ProjectID: projectID}, time.Now().Add(24*time.Hour), false))
	require.NoError(t, testCore.DeleteGroup(ctx, admin.ID, deletedGroup.ID))

	setupTok, err := testCore.Storage().CreateSetupToken(ctx, &models.SetupToken{
		TokenHash: "ceiling-walk-setup-token-hash-00000000000000000000000000001",
		Purpose:   "account_setup", SubjectUserID: &setupTarget.ID, SubjectEmail: setupTarget.Email,
		State: "active", ExpiresAt: time.Now().Add(time.Hour), CreatedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	require.NoError(t, testCore.Storage().CreateWebAuthnCredential(ctx, &models.WebAuthnCredential{
		UserID: regularUser.ID, CredentialID: []byte("ceiling-walk-cred-id"), Name: "ceiling-walk-passkey", CreatedAt: time.Now(),
	}))
	webauthnCred, err := testCore.Storage().GetWebAuthnCredentialByCredID(ctx, []byte("ceiling-walk-cred-id"), regularUser.ID)
	require.NoError(t, err)

	pendingInvitation, err := testCore.Storage().CreateProjectInvitation(ctx, &models.ProjectInvitation{
		ProjectID: projectID, Email: "ceiling-walk-invitee@example.com", Role: "viewer", State: "pending",
		InvitedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	breakGlassActivation, err := testCore.Storage().CreateBreakGlassActivation(ctx, &models.BreakGlassActivation{
		ProjectID: projectID, UserID: regularUser.ID, RoleID: normalRole.ID, RoleName: normalRole.Name,
		Justification: "ceiling-walk fixture", State: "active", CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	campaign, err := testCore.Storage().CreateAccessReviewCampaign(ctx, &models.AccessReviewCampaign{
		ProjectID: projectID, Name: "ceiling-walk-campaign", State: "open", CreatedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)
	require.NoError(t, testCore.Storage().CreateAccessReviewItems(ctx, []*models.AccessReviewItem{{
		CampaignID: campaign.ID, PrincipalType: "user", PrincipalID: regularUser.ID, PrincipalName: regularUser.Username,
		Source: "role", RoleID: normalRole.ID, RoleName: normalRole.Name, AccessLevel: "member",
		EnvironmentID: envID, Decision: "pending",
	}}))
	items, err := testCore.Storage().ListAccessReviewItems(ctx, campaign.ID)
	require.NoError(t, err)
	require.NotEmpty(t, items)

	return systemCeilingFixtures{
		serverURL:             server.URL,
		token:                 token,
		nodeToken:             nodeToken,
		permissionedNodeToken: permissionedNodeToken,
		usersWriteNodeToken:   usersWriteNodeToken,
		rolesAssignNodeToken:  rolesAssignNodeToken,
		rolesAssignToken:      rolesAssignToken,
		usersWriteToken:       usersWriteToken,
		projectID:             projectID,
		envID:                 envID,
		plainMachine:          plainMachine.ID,
		adminMachine:          adminMachine.ID,
		revokedMach:           revokedMachine.ID,
		plainCredID:           plainCred.ID,
		revokedCredID:         revokedCred.ID,
		bindingID:             binding.ID,
		normalRoleID:          normalRole.ID,
		adminRoleID:           adminRole.ID,
		secondAdminUserID:     secondAdmin.ID,
		setupTargetUserID:     setupTarget.ID,

		regularUserID:        regularUser.ID,
		dependentSecretID:    dependent.ID,
		dependsOnSecretID:    dependsOn.ID,
		activeSecretID:       activeSecret.ID,
		suspendedSecretID:    suspendedSecret.ID,
		nonAdminGroupID:      nonAdminGroup.ID,
		adminTierGroupID:     adminTierGroup.ID,
		deletedGroupID:       deletedGroup.ID,
		setupTokenID:         setupTok.ID,
		webauthnCredentialID: webauthnCred.ID,
		pendingInvitationID:  pendingInvitation.ID,

		breakGlassActivationID: breakGlassActivation.ID,
		accessReviewCampaignID: campaign.ID,
		accessReviewItemID:     items[0].ID,
	}
}

// createSystemWriteOnlyNodeToken mints a node-type machine-identity bearer
// token holding ONLY system.write at global scope -- the machine-credential
// analogue of createSystemWriteOnlyToken (system_write_ceiling_test.go), and
// principal (c) in the walk's 3-principal model. Deliberately distinct from
// createNodeToken (integration_test.go): that helper assigns the machine the
// full "admin" role (adminRoleNames, internal/core/authz.go), an
// admin-tier bypass that trivially passes every check in this file and so
// cannot serve as a narrow-permission principal. Reuses the
// "ceiling_test_system_writer" role BY NAME rather than re-creating it --
// role names are unique per-install, not per-actor, and
// createSystemWriteOnlyToken (called earlier in the same fixture setup)
// already seeded it. AssignMachineRole is called at the STORAGE layer
// directly (not core.KeyorixCore.AssignMachineRole), mirroring
// createNodeToken's own reasoning: the core-layer method's ceiling requires
// scope.ProjectID to match the machine identity's own project, so it can
// never grant a truly global-scope permission.
func createSystemWriteOnlyNodeToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	mi, admin, projectID := createNodeIdentityAndAdmin(t, c)
	role, err := c.Storage().GetRoleByName(ctx, "ceiling_test_system_writer")
	require.NoError(t, err, "createSystemWriteOnlyToken must run earlier in this fixture setup to seed this role")
	require.NoError(t, c.Storage().AssignMachineRole(ctx, mi.ID, role.ID, coreStorage.Scope{}))
	result, err := c.IssueMachineToken(ctx, projectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "test-node-system-write-only-token"})
	require.NoError(t, err)
	return result.PlainToken
}

// createUsersWriteNodeToken mints a node-type machine-identity bearer token
// holding system.write + users.write at global scope -- the machine-actor
// analogue of createSystemWriteAndUsersWriteToken, reusing that role by name.
// Used for Task 3's positive controls on the real-caller routes gated by
// users.write (F5, Group create/update/delete): CLI client mode's bearer
// token can be a machine credential, and core.AuthorizePrincipal's machine
// branch is untested by a human-only control.
func createUsersWriteNodeToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	mi, admin, projectID := createNodeIdentityAndAdmin(t, c)
	role, err := c.Storage().GetRoleByName(ctx, "ceiling_test_system_writer_users_write")
	require.NoError(t, err, "createSystemWriteAndUsersWriteToken must run earlier in this fixture setup to seed this role")
	require.NoError(t, c.Storage().AssignMachineRole(ctx, mi.ID, role.ID, coreStorage.Scope{}))
	result, err := c.IssueMachineToken(ctx, projectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "test-node-users-write-token"})
	require.NoError(t, err)
	return result.PlainToken
}

// createRolesAssignNodeToken is createUsersWriteNodeToken's roles.assign
// sibling, for the UpdateInvitationProxy positive control.
func createRolesAssignNodeToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()
	mi, admin, projectID := createNodeIdentityAndAdmin(t, c)
	role, err := c.Storage().GetRoleByName(ctx, "ceiling_test_system_writer_roles_assign")
	require.NoError(t, err, "createSystemWriteAndRolesAssignToken must run earlier in this fixture setup to seed this role")
	require.NoError(t, c.Storage().AssignMachineRole(ctx, mi.ID, role.ID, coreStorage.Scope{}))
	result, err := c.IssueMachineToken(ctx, projectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "test-node-roles-assign-token"})
	require.NoError(t, err)
	return result.PlainToken
}

// doSystemCeilingRequest issues method/path with body (nil for none) as f's
// system.write-only human caller.
func doSystemCeilingRequest(t *testing.T, f systemCeilingFixtures, method, path string, body any) (int, string) {
	t.Helper()
	return doSystemCeilingRequestAs(t, f, f.token, method, path, body)
}

// doSystemCeilingRequestAs generalizes doSystemCeilingRequest to an explicit
// bearer token, so a row can exercise the SAME route as a different caller
// class (e.g. f.nodeToken, f.rolesAssignToken, f.usersWriteToken).
func doSystemCeilingRequestAs(t *testing.T, f systemCeilingFixtures, token, method, path string, body any) (int, string) {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(b)
	} else {
		reader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, f.serverURL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, err = buf.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, buf.String()
}

// requireSystemCeilingRefused is the shared assertion every deny row in this
// file ends with: a caller must never see a 2xx.
func requireSystemCeilingRefused(t *testing.T, status int, body, routeDesc string) {
	t.Helper()
	require.NotContainsf(t, []int{200, 201, 202, 204}, status,
		"CEILING VIOLATED: %s succeeded (HTTP %d) — got body %s", routeDesc, status, body)
}

// requireSystemCeilingRefusedForHumanAndPermissionedNode runs the SAME
// request as BOTH dimension (a) (f.token: human, system.write only) and
// dimension (c) (f.permissionedNodeToken: node credential holding ONLY
// system.write) and asserts both are refused by this route's OWN,
// route-specific ceiling -- not the /system group's shared gate, which BOTH
// principals pass identically (see
// TestSystemGroupGateHonorsSystemWriteAcrossActorTypes, which verifies the
// gate-level property once, for every route, rather than re-deriving it
// here). Subtests keep a failure of one dimension from masking the other.
// This is the mechanism that closes the 9 node-credential tests dropped when
// system_write_ceiling_table_test.go / _users_test.go were deleted (see this
// branch's deleted-test accounting) -- generalized to every deny-checked
// route in this file, not just the original 9.
func requireSystemCeilingRefusedForHumanAndPermissionedNode(t *testing.T, f systemCeilingFixtures, method, path string, body any, routeDesc string) {
	t.Helper()
	t.Run("dimension-a/human-system-write-only", func(t *testing.T) {
		status, respBody := doSystemCeilingRequestAs(t, f, f.token, method, path, body)
		requireSystemCeilingRefused(t, status, respBody, routeDesc+" (human, system.write only)")
	})
	t.Run("dimension-c/node-credential-system-write-only", func(t *testing.T) {
		status, respBody := doSystemCeilingRequestAs(t, f, f.permissionedNodeToken, method, path, body)
		requireSystemCeilingRefused(t, status, respBody, routeDesc+" (node credential, system.write only)")
	})
}

// chiParamPattern matches a chi route-pattern placeholder like "{id}" or
// "{roleId}", for substituteRouteParams below.
var chiParamPattern = regexp.MustCompile(`\{[^}]+\}`)

// substituteRouteParams replaces every {param} in a chi route pattern with a
// syntactically-valid placeholder value ("1"). Used only by the gate-level
// probe below, which never needs the placeholder to resolve to a REAL row --
// the property under test (did the /system group's own middleware gate deny
// the request) is decided before any handler ever reads a path param.
func substituteRouteParams(route string) string {
	return chiParamPattern.ReplaceAllString(route, "1")
}

// systemGroupGateDenied reports whether status/body is SPECIFICALLY the
// /system route group's own RequirePermission(system.write) middleware
// denial (server/middleware/auth.go's forbiddenResponse:
// {"error":"Forbidden","message":"Insufficient permissions","code":403}) --
// structurally distinct from every /system proxy handler's OWN error
// envelope (writeRemoteAPIError: {"success":false,"data":...,
// "error":{"code":"...","message":"..."}}, where "error" is an OBJECT, not a
// string -- json.Unmarshal into the string-typed field below fails and this
// returns false for that shape). This lets a probe with a synthetic,
// possibly-invalid path/body still distinguish "never reached the handler"
// from "reached the handler, and it did something else" (succeeded, 404'd on
// a fake ID, or refused for its OWN route-specific reason) without needing a
// fully valid request for every route in the walk.
func systemGroupGateDenied(status int, body string) bool {
	if status != http.StatusForbidden {
		return false
	}
	var parsed struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return false
	}
	return parsed.Error == "Forbidden" && parsed.Message == "Insufficient permissions"
}

// ── Route classification ─────────────────────────────────────────────────────
//
// Every mutating route under /api/v1/system falls into exactly one of the
// three maps below. TestSystemWriteOnlyCeilingWalk fails outright if a
// walked route is in none of them.

// systemCeilingReadOnly: registered as a mutating HTTP method but is actually
// a read (no state change) — excluded from the mutating population entirely,
// not "reviewed and allowed."
var systemCeilingReadOnly = map[string]string{
	"POST /api/v1/system/mfa/stepup-grants/active": "GetActiveMFAStepUpGrantProxy takes a body (why it's POST, not GET) " +
		"but performs no mutation at all -- it only reads whether an active step-up grant exists for a (user, purpose) pair.",
}

// systemCeilingAllowlist: system.write alone is the reviewed, sufficient
// ceiling for this route. Each reason states WHY -- no human-facing
// equivalent exists to be weaker than, the check is self-contained and
// already independently verified, or the operation genuinely confers no
// privilege by itself.
//
// Principal applicability (user-directed 3-dimension extension of F6): the
// DEFAULT for every entry below, unless its own text says otherwise, is:
//   - (a) human, system.write only -- allowed, per the entry's own reason.
//   - (b) bare node/machine credential, zero role grants -- refused at the
//     /system group's own gate (ADR-085) -- verified for EVERY mutating
//     route, allowlisted or not, by TestSystemGroupGateHonorsSystemWriteAcrossActorTypes.
//   - (c) node/machine credential holding ONLY system.write -- passes that
//     SAME gate, the same way (a) does -- also verified by
//     TestSystemGroupGateHonorsSystemWriteAcrossActorTypes, for every route.
//     This is GATE-LEVEL verification only: it does not re-run each route's
//     own deeper reasoning (e.g. an admin-tier check that pre-dates this
//     branch) against a machine actor specifically -- where that reasoning
//     is itself actor-agnostic (a role-name/state check with no actorType
//     branch, confirmed by grepping internal/core for actorIsMachine/
//     ActorTypeMachine-conditioned logic across every allowlisted route's
//     backing function), gate-level passing is the complete picture, same
//     as it is for dimension (a). Three routes below are NOT default: their
//     own entry names the exception and the dedicated test that proves it.
var systemCeilingAllowlist = map[string]string{
	"POST /api/v1/system/login-attempts": "no human-facing equivalent -- internal per-replica rate-limit bookkeeping, " +
		"CORE-RATE-003-hardened (validated/clamped in core.RecordLoginAttemptRelay).",
	"POST /api/v1/system/login-attempts/prune": "no human-facing equivalent; core.PruneLoginAttempts clamps the " +
		"caller-supplied 'before' to its own retention default -- narrows only, never widens.",
	"POST /api/v1/system/invitations": "CreateInvitationProxy re-derives requireAuthorityForRole for Role/SystemRole/" +
		"every AssignmentsJSON entry -- a system.write-only caller with no other grant cannot invite with any role " +
		"that bundles a permission it doesn't hold.",
	"POST /api/v1/system/access-requests": "CreateAccessRequestProxy forces State=pending unconditionally; the " +
		"human-facing create route is self-service (no permission required) anyway, so system.write is already " +
		"strictly stronger.",
	"PUT /api/v1/system/access-requests/{id}": "UpdateAccessRequestProxy re-derives maker != checker plus " +
		"admin/role-grant authority on the 'approved' transition specifically.",
	"POST /api/v1/system/access-requests/{id}/approvals": "same ceiling as UpdateAccessRequestProxy above -- " +
		"maker != checker re-derived on approval.",
	"POST /api/v1/system/notifications": "core applies no authorization ceiling to notification creation at all, " +
		"and models.Notification carries no actor/origin field a forged caller could exploit.",
	"DELETE /api/v1/system/groups/{id}/members/{userId}": "RemoveGroupMemberProxy's only check is " +
		"guardLastGlobalAdminMembership, a target-state invariant (would this strand the group's last admin-tier " +
		"member) -- not actor-dependent. Removal is the safe direction, same reasoning as RemoveMachineRoleProxy.",
	"DELETE /api/v1/system/machine-identities/{id}/roles/{roleId}": "RemoveMachineRoleProxy: no ceiling anywhere, " +
		"local or proxy -- removal is safe-direction (node-credential classification registry).",
	"PUT /api/v1/system/machine-identities/{id}/transition": "TransitionMachineIdentityStateProxy: illegal " +
		"transitions (e.g. revoked->active) are refused by core.IsValidMachineTransition regardless of caller -- " +
		"see TestSystemWriteCeiling_TransitionMachineIdentityStateProxy_RejectsIllegalTransition below.",
	"GET /api/v1/system/machine-identities/{id}/credentials": "read.",
	"PUT /api/v1/system/machine-credentials/{id}": "UpdateMachineIdentityCredentialProxy only ever applies " +
		"Classification from the wire body -- Revoked/TokenHash/ExpiresAt are never read, so a caller cannot " +
		"resurrect a revoked credential regardless of authority.",
	"POST /api/v1/system/machine-credentials/{id}/touch": "TouchMachineIdentityCredentialProxy: documented " +
		"no-independent-ceiling exception (see the raw-storage-bypass registry) -- touching last-used metadata on " +
		"a credential the caller can already reach confers nothing.",
	"DELETE /api/v1/system/machine-oidc-bindings/{id}": "DeleteOIDCBindingProxy: core.DeleteOIDCBinding verifies " +
		"the binding actually belongs to the named machine before deleting -- ownership, not caller authority " +
		"(deleting a binding you're relaying on behalf of is legitimate; there is no separate authority ceiling).",
	"POST /api/v1/system/setup-tokens/supersede": "SupersedeSetupTokensProxy: the IssueSetupToken step this backs " +
		"(SupersedeActiveSetupTokens) has no caller-authorization gate of its own -- an unconditional exact-match " +
		"(purpose, email[, project]) bulk state-flip, not scoped to any one user's authority to withhold.",
	"POST /api/v1/system/connect-grants": "no route registered -- reads only.",
	"POST /api/v1/system/sso-state": "ephemeral CSRF-state/nonce row for an in-flight SSO ceremony; no human-facing " +
		"equivalent to compare against, nothing to authorize.",
	"POST /api/v1/system/sso-state/consume": "single-use consume of the same ephemeral ceremony row -- same reasoning.",
	"POST /api/v1/system/project-memberships": "CreateMembershipProxy: fixed (#1578) -- re-derives " +
		"RequireGranterHoldsRolePermissions against the requested membership Role at the target project scope " +
		"before persisting, and forces InvitedBy to the authenticated caller.",
	"PUT /api/v1/system/project-memberships/{id}/transition": "TransitionMembershipProxy: fixed (#1546) -- fully " +
		"delegates to core.TransitionMembership, which re-derives the state-machine legality check and reads only " +
		"(projectID, membershipID, to, actorID) off the wire -- every other field, including Role, is ignored.",
	"PATCH /api/v1/system/webauthn/credentials/advance-counter": "AdvanceWebAuthnCredentialCounterProxy performs a " +
		"locked compare-and-swap on a signature counter -- the anti-clone TOCTOU fix (#306/#517), not an authority " +
		"decision; any caller reaching it can only ever advance a counter forward under a lock, never forge state.",
	"POST /api/v1/system/webauthn/sessions":         "ephemeral WebAuthn ceremony session row -- no human-facing equivalent.",
	"POST /api/v1/system/webauthn/sessions/consume": "single-use consume of the same ephemeral ceremony row.",
	"POST /api/v1/system/legal-hold": "CreateLegalHoldProxy: core.PlaceLegalHold requires admin-tier authority " +
		"(isGlobalAdminRoleName, #377) unconditionally -- confirmed by direct read of legal_hold.go, not the doc " +
		"comment; a system.write-only, non-admin caller is refused today.",
	"PUT /api/v1/system/legal-hold/{id}": "UpdateLegalHoldProxy: core.LiftLegalHold requires placer-or-admin-tier " +
		"authority (#157) unconditionally -- confirmed by direct read; same as CreateLegalHoldProxy above.",
	"POST /api/v1/system/risk-exceptions": "CreateRiskExceptionProxy: creation alone confers nothing -- dual " +
		"control's real gate is the separate, per-actor-ceiling-gated approve step below. NOT the default principal " +
		"applicability: (c) is REFUSED, not allowed -- core.CreateRiskException denies ANY machine actor " +
		"unconditionally regardless of permission ('dual control' means two humans), confirmed by direct code read " +
		"and TestSystemWriteCeiling_CreateRiskExceptionProxy_RefusesMachineActorByDesign below. ApproveRiskException " +
		"has the identical actorIsMachine check.",
	"PUT /api/v1/system/risk-exceptions/{id}/revoke": "RevokeRiskExceptionProxy: core.RevokeRiskException has no " +
		"actor-authority check by design (#1529 territory, an audit-completeness gap, not a policy bypass).",
	"POST /api/v1/system/sod-policies": "CreateSoDPolicyProxy: human-facing POST /api/v1/sod/policies requires " +
		"the IDENTICAL permission (permSystemWrite) -- no mismatch possible by construction.",
	"DELETE /api/v1/system/sod-policies/{id}": "DeleteSoDPolicyProxy: same as create above -- identical permission " +
		"on both surfaces.",
	"POST /api/v1/system/retention/role-grants/purge-expired": "DeleteExpiredRoleGrantsProxy: core.RemoveExpiredRoleGrants " +
		"has no actor ceiling either -- an unconditional, time-bounded system sweep (#1529 territory).",
	"POST /api/v1/system/retention/share-records/purge-expired": "DeleteExpiredShareRecordsProxy: same shape as " +
		"the role-grants purge above.",
	"POST /api/v1/system/users/with-role-grants": "CreateUserWithRoleGrantsProxy: ValidateRoleGrantAuthority runs " +
		"unconditionally for every grant in the request -- escalation-by-proxy re-derived per role.",
	"POST /api/v1/system/rbac/assign-role-with-expiry": "AssignRoleWithExpiryProxy: fixed (#1542/#1552) -- routes " +
		"through core.AssignUserRoleWithExpiry unconditionally; requireGranterHoldsRolePermissions runs against " +
		"every caller's own authority.",
	"POST /api/v1/system/rbac/assign-role-to-group-with-expiry": "AssignRoleToGroupWithExpiryProxy: fixed (#1542) -- " +
		"routes through core.AssignGroupRoleWithExpiry unconditionally; requireAuthorityForRole is admin-tier-only " +
		"and actorID==0-safe.",
	"POST /api/v1/system/rbac/remove-all-project-role-grants": "RemoveAllProjectRoleGrantsProxy: fixed (#1542) -- " +
		"routes through core.RemoveProjectMember unconditionally, restoring guardLastProjectAdmin (target-state).",
	"POST /api/v1/system/rbac/clear-project-secret-ownership": "ClearProjectSecretOwnershipProxy: confirmed false " +
		"positive -- a best-effort CLEANUP side effect inside RemoveProjectMember, never independently gated.",
	"POST /api/v1/system/rbac/delete-secret-acls-by-user-and-project": "DeleteSecretACLsByUserAndProjectProxy: " +
		"same shape as clear-project-secret-ownership above.",
	"POST /api/v1/system/rbac/global-admin-role/remove-guarded": "RemoveGlobalAdminRoleGuardedProxy: fixed -- " +
		"requires roles.assign at global scope, the same authority the human-facing DELETE /user-roles route " +
		"requires.",
	"POST /api/v1/system/mfa/totp-step-used": "MarkTOTPStepUsedProxy: reviewed, not independently ceiling-checked " +
		"on this branch. A caller-scoping fix was attempted and reverted: TestConformance_MarkTOTPStepUsed proved " +
		"the real caller shape needs to act across principals, so a naive per-principal restriction broke a " +
		"legitimate case. See docs/findings/2026-09-21-FINDING-system-proxy-target-authority.md for the analysis.",
	"POST /api/v1/system/mfa/stepup-grants/prune": "PruneMFAStepUpGrantsProxy: core.PruneMFAStepUpGrants clamps " +
		"the caller-supplied 'before' to the stricter of its own default retention -- narrows only.",
	"DELETE /api/v1/system/projects/{id}": "DeleteProjectProxy: fixed (#1657) -- RequireScopedPermission(permSecretsDelete, " +
		"projectScope) layered on top of the group's blanket gate, mirroring the human-facing DeleteProject route. " +
		"NOT the default principal applicability: (c) needs secrets.delete IN ADDITION to system.write (see " +
		"systemCeilingLayeredPermission) -- a system.write-only machine is correctly refused by this SECOND layer, " +
		"proven both directions by TestSystemCeilingLayeredPermission_DeleteProjectProxy_MachineSecretsDeleteHolder_Succeeds " +
		"(positive) and the generic gate walk's layered-permission branch (negative).",
	"POST /api/v1/system/projects/{id}/delete-if-empty": "DeleteProjectIfEmptyProxy: same scoped-permission fix as " +
		"DeleteProjectProxy above -- same NOT-default principal applicability (secrets.delete required beyond " +
		"system.write), not independently re-proven positive here (identical middleware wrapper, same permission).",
	"DELETE /api/v1/system/environments/{id}": "DeleteEnvironmentProxy: fixed (#1648) -- the same scoped-permission " +
		"treatment DeleteProjectProxy got, scoped to the environment's own project -- same NOT-default principal " +
		"applicability as DeleteProjectProxy above.",
	"POST /api/v1/system/audit/event": "IngestAuditEventProxy: raw storage write, no audit POLICY decision made " +
		"here (event type/severity/actor are the CALLING server's own core.KeyorixCore's decision) -- confirmed " +
		"in the raw-storage-bypass registry.",
}

// systemCeilingLayeredPermission: an allowlisted route whose "system.write is
// sufficient" reasoning is conditioned on a SECOND, stronger permission
// layered on top by its own dedicated middleware (RequireScopedPermission),
// not the /system group's shared system.write gate alone. f.permissionedNodeToken
// holds ONLY system.write, so it is CORRECTLY refused by that second layer --
// found empirically by TestSystemGroupGateHonorsSystemWriteAcrossActorTypes
// when its default "every allowlisted route must pass the gate for dimension
// (c)" assumption broke on these three, which turned out to be a flaw in
// that assumption (their own allowlist reason already names the extra
// layer), not a gap in the routes themselves. Both directions get an
// explicit test below: refused without the extra permission, allowed with
// it (secrets.delete) -- proving the second layer, like the first, is
// actor-type-agnostic, not merely "not obviously broken."
var systemCeilingLayeredPermission = map[string]string{
	"DELETE /api/v1/system/projects/{id}":               "secrets.delete, scoped to the project (#1657).",
	"POST /api/v1/system/projects/{id}/delete-if-empty": "secrets.delete, scoped to the project (#1657).",
	"DELETE /api/v1/system/environments/{id}":           "secrets.delete, scoped to the environment's project (#1648).",
}

// systemCeilingDenyChecked: a dedicated Test* function -- in this file, or
// (for F5) in users_active_transition_proxy_ceiling_test.go -- sends a
// request as a system.write-only caller and asserts it is refused. The set
// value is unused; only key presence matters.
var systemCeilingDenyChecked = map[string]bool{
	// The seven-plus-four item fix set (system-proxy-target-authority audit).
	"PUT /api/v1/system/users/{id}/active-transition":           true, // F5
	"POST /api/v1/system/secret-dependencies/exclusive":         true,
	"PUT /api/v1/system/secrets/{id}/transition-status":         true,
	"POST /api/v1/system/groups":                                true,
	"PUT /api/v1/system/groups/{id}":                            true,
	"DELETE /api/v1/system/groups/{id}":                         true,
	"POST /api/v1/system/groups/{id}/restore":                   true,
	"POST /api/v1/system/setup-tokens/{id}/expire":              true,
	"PUT /api/v1/system/webauthn/credentials/{id}":              true,
	"PUT /api/v1/system/invitations/{id}":                       true,
	"POST /api/v1/system/break-glass/{id}/revoke":               true,
	"PUT /api/v1/system/access-review-campaigns/items/{itemID}": true,
	"POST /api/v1/system/access-review-campaigns":               true,
	"POST /api/v1/system/access-review-campaigns/{id}/items":    true,

	// Already-fixed rows ported from system_write_ceiling_table_test.go /
	// system_write_ceiling_table_users_test.go (the two files this walk
	// replaces) -- kept as rows, not re-litigated.
	"POST /api/v1/system/machine-identities":                           true,
	"POST /api/v1/system/machine-credentials":                          true,
	"POST /api/v1/system/machine-identities/{id}/roles/{roleId}":       true,
	"POST /api/v1/system/machine-oidc-bindings":                        true,
	"POST /api/v1/system/rbac/global-admin-role/remove-guarded":        true,
	"POST /api/v1/system/setup-tokens":                                 true,
	"POST /api/v1/system/users/{id}/personal-access-tokens/revoke-all": true,
	"POST /api/v1/system/users/{id}/sessions/delete-except":            true,
	"POST /api/v1/system/groups/{id}/members":                          true,
	"POST /api/v1/system/machine-credentials/{id}/revoke":              true,
	"PUT /api/v1/system/risk-exceptions/{id}/approve":                  true,
}

// ── The walk ──────────────────────────────────────────────────────────────────

// mutatingHTTPMethod is the set of methods TestSystemWriteOnlyCeilingWalk
// treats as "mutating" -- GET/HEAD/OPTIONS are never in this population
// regardless of what route they're registered on.
var mutatingHTTPMethod = map[string]bool{
	http.MethodPost: true, http.MethodPut: true, http.MethodDelete: true, http.MethodPatch: true,
}

// TestSystemWriteOnlyCeilingWalk is F6: a real chi.Walk over the router's
// actual registered routes (not a hand-copied list nobody re-checks against
// the source -- the #1511/#1524 lesson this campaign has hit twice before).
// Every mutating route under /api/v1/system must be classified in exactly
// one of systemCeilingReadOnly / systemCeilingAllowlist / systemCeilingDenyChecked.
// A route in none of the three fails the walk outright.
func TestSystemWriteOnlyCeilingWalk(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	testCore := newTestCore(t)
	handler, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	routes, ok := handler.(chi.Routes)
	require.True(t, ok, "router must expose chi.Routes for walking")

	var (
		checked   int
		uncovered []string
	)
	walkErr := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/system") || !mutatingHTTPMethod[method] {
			return nil
		}
		key := method + " " + route
		checked++
		switch {
		case systemCeilingReadOnly[key] != "":
		case systemCeilingAllowlist[key] != "":
		case systemCeilingDenyChecked[key]:
		default:
			uncovered = append(uncovered, key)
		}
		return nil
	})
	require.NoError(t, walkErr)
	require.Greaterf(t, checked, 40, "sanity: the walk should cover most of the /system mutating surface (got %d)", checked)
	require.Emptyf(t, uncovered,
		"route(s) with no ceiling classification -- add an entry to systemCeilingReadOnly, "+
			"systemCeilingAllowlist, or a Test* function + systemCeilingDenyChecked entry: %s", strings.Join(uncovered, ", "))
}

// TestSystemGroupGateHonorsSystemWriteAcrossActorTypes is dimensions (b) and
// (c)'s GATE-LEVEL half of the walk's 3-principal model (user-directed
// extension of F6, restructuring the 9 node-credential tests dropped when
// system_write_ceiling_table_test.go / _users_test.go were deleted). For
// EVERY mutating /system route: a bare node/machine credential holding zero
// role grants (f.nodeToken) must be refused at the /system group's own
// RequirePermission(system.write) gate (server/http/router.go, ADR-085) --
// dimension (b) -- and a node/machine credential holding ONLY system.write
// (f.permissionedNodeToken) must NOT be refused at that same gate --
// dimension (c) at the gate level, matching how dimension (a)'s human
// system.write-only caller already passes it.
//
// This specifically exercises the MACHINE-actor branch of
// core.AuthorizePrincipal (internal/core/authz.go: GetMachineRoleIDsAt +
// RoleSetHasPermission), a materially different code path from the human
// branch (c.Authorize) -- passing for one caller class is not evidence for
// the other, which is why this is a real, additional check and not a
// re-statement of the existing human-only walk.
//
// Scope: this verifies GATE-LEVEL behavior only (systemGroupGateDenied
// distinguishes the middleware's own denial from anything a handler itself
// returns, via synthetic placeholder path params/bodies that don't need to
// resolve to a real row). For an ALLOWLISTED route, gate-level passing IS
// the complete verification its own reviewed reasoning claims -- "system.write
// alone is sufficient" means nothing beyond the gate should matter. For a
// DENY-CHECKED route, gate-level passing is necessary but not sufficient --
// each TestSystemWriteCeiling_* function below additionally sends its real,
// valid request as f.permissionedNodeToken via
// requireSystemCeilingRefusedForHumanAndPermissionedNode, proving the
// route's OWN deeper ceiling (not just the shared gate) also holds for a
// node-type actor.
func TestSystemGroupGateHonorsSystemWriteAcrossActorTypes(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	testCore := newTestCore(t)
	handler, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	routes, ok := handler.(chi.Routes)
	require.True(t, ok, "router must expose chi.Routes for walking")

	f := setupSystemCeilingFixtures(t)

	var walked []string
	walkErr := chi.Walk(routes, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if !strings.HasPrefix(route, "/api/v1/system") || !mutatingHTTPMethod[method] {
			return nil
		}
		key := method + " " + route
		if systemCeilingReadOnly[key] != "" {
			return nil // not part of the mutating population at all -- mirrors TestSystemWriteOnlyCeilingWalk's own scope.
		}
		walked = append(walked, key)
		return nil
	})
	require.NoError(t, walkErr)
	require.Greaterf(t, len(walked), 40, "sanity: should cover most of the /system mutating surface (got %d)", len(walked))

	for _, key := range walked {
		method, route, found := strings.Cut(key, " ")
		require.True(t, found)
		path := substituteRouteParams(route)

		t.Run(key+"/dimension-b-bare-node-denied-at-gate", func(t *testing.T) {
			status, body := doSystemCeilingRequestAs(t, f, f.nodeToken, method, path, nil)
			require.Truef(t, systemGroupGateDenied(status, body),
				"ADR-085: a bare node credential (zero role grants) must be refused at the /system group's own "+
					"system.write gate for EVERY mutating route -- got status=%d body=%s", status, body)
		})

		t.Run(key+"/dimension-c-permissioned-node-passes-gate", func(t *testing.T) {
			status, body := doSystemCeilingRequestAs(t, f, f.permissionedNodeToken, method, path, nil)
			if reason := systemCeilingLayeredPermission[key]; reason != "" {
				// This route's OWN allowlist reason names a second, stronger
				// permission layered on top of system.write (see
				// systemCeilingLayeredPermission's own doc) -- f.permissionedNodeToken
				// does not hold it, so refusal is the CORRECT outcome here, the
				// opposite of every other allowlisted route. The dedicated
				// TestSystemCeilingLayeredPermission_* pair below additionally
				// proves the positive direction (allowed WITH the extra
				// permission) with a real, non-synthetic request.
				require.Truef(t, systemGroupGateDenied(status, body) || status == http.StatusForbidden,
					"%s requires %s beyond system.write -- a node credential holding only system.write must still be "+
						"refused -- got status=%d body=%s", key, reason, status, body)
				return
			}
			require.Falsef(t, systemGroupGateDenied(status, body),
				"a node credential holding ONLY system.write must pass the /system group's own gate the same way "+
					"the human system.write-only caller does (dimension a) -- got status=%d body=%s", status, body)
		})
	}
}

// ── Deny-check rows: the seven-plus-four fix set ────────────────────────────────

func TestSystemWriteCeiling_CreateSecretDependencyExclusiveProxy_RequiresSecretsWriteOnBothEndpoints(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/secret-dependencies/exclusive", map[string]any{
		"project_id": f.projectID, "dependent_secret_id": f.dependentSecretID, "depends_on_secret_id": f.dependsOnSecretID, "note": "attempt",
	}, "CreateSecretDependencyExclusiveProxy")
}

func TestSystemWriteCeiling_TransitionSecretStatusProxy_SuspendRequiresSecretsWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/secrets/%d/transition-status", f.activeSecretID), map[string]any{
		"secret": map[string]any{"id": f.activeSecretID, "status": "suspended", "updated_at": time.Now()}, "from_status": "active",
	}, "TransitionSecretStatusProxy (suspend)")
}

func TestSystemWriteCeiling_TransitionSecretStatusProxy_ResumeRequiresSecretsWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/secrets/%d/transition-status", f.suspendedSecretID), map[string]any{
		"secret": map[string]any{"id": f.suspendedSecretID, "status": "active", "updated_at": time.Now()}, "from_status": "suspended",
	}, "TransitionSecretStatusProxy (resume)")
}

func TestSystemWriteCeiling_CreateGroupProxy_RequiresUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/groups", map[string]any{
		"name": "ceiling-walk-attempted-group", "description": "x",
	}, "CreateGroupProxy")
}

func TestSystemWriteCeiling_UpdateGroupProxy_RequiresUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/groups/%d", f.nonAdminGroupID), map[string]any{
		"name": "renamed", "description": "x",
	}, "UpdateGroupProxy")
}

func TestSystemWriteCeiling_DeleteGroupProxy_RequiresUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodDelete, fmt.Sprintf("/api/v1/system/groups/%d", f.nonAdminGroupID), nil, "DeleteGroupProxy")
}

func TestSystemWriteCeiling_RestoreGroupProxy_RequiresRolesAssign(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/groups/%d/restore", f.deletedGroupID), nil, "RestoreGroupProxy")
}

func TestSystemWriteCeiling_ExpireSetupTokenProxy_RequiresUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/setup-tokens/%d/expire", f.setupTokenID), nil, "ExpireSetupTokenProxy")
}

func TestSystemWriteCeiling_UpdateWebAuthnCredentialProxy_RequiresOwnershipOrUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	// f.token/f.permissionedNodeToken each authenticate as a DIFFERENT
	// principal than regularUserID, who owns this credential -- not
	// ownership, and no users.write either.
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/webauthn/credentials/%d", f.webauthnCredentialID), map[string]any{
		"user_id": f.regularUserID, "credential_id": []byte("ceiling-walk-cred-id"), "disabled": true,
	}, "UpdateWebAuthnCredentialProxy")
}

func TestSystemWriteCeiling_UpdateInvitationProxy_RequiresRolesAssignScopedToProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/invitations/%d", f.pendingInvitationID), map[string]any{
		"state": "revoked",
	}, "UpdateInvitationProxy")
}

func TestSystemWriteCeiling_RevokeBreakGlassActivationProxy_RequiresRolesAssignScopedToProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/break-glass/%d/revoke", f.breakGlassActivationID), map[string]any{}, "RevokeBreakGlassActivationProxy")
}

func TestSystemWriteCeiling_UpdateAccessReviewItemProxy_RequiresRolesAssignScopedToProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/access-review-campaigns/items/%d", f.accessReviewItemID), map[string]any{
		"decision": "attested", "reason": "attempt",
	}, "UpdateAccessReviewItemProxy")
}

func TestSystemWriteCeiling_CreateAccessReviewCampaignProxy_RequiresRolesAssignScopedToProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/access-review-campaigns", map[string]any{
		"project_id": f.projectID, "name": "ceiling-walk-attempted-campaign",
	}, "CreateAccessReviewCampaignProxy")
}

func TestSystemWriteCeiling_CreateAccessReviewItemsProxy_RequiresRolesAssignScopedToProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/access-review-campaigns/%d/items", f.accessReviewCampaignID), map[string]any{
		"items": []map[string]any{{"principal_type": "user", "principal_id": f.regularUserID, "source": "role", "access_level": "member"}},
	}, "CreateAccessReviewItemsProxy")
}

// ── Deny-check rows: ported from system_write_ceiling_table_test.go /
// system_write_ceiling_table_users_test.go (already-fixed, kept as rows) ────────

func TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_EnforcesPrivilegeCeiling(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": f.adminMachine,
		"token_hash":          "cccc000000000000000000000000000000000000000000000000000000000003",
		"token_prefix":        "mid_forged_admin",
	}, "CreateMachineIdentityCredentialProxy (admin-tier target, MACH-001)")
}

func TestSystemWriteCeiling_AssignMachineRoleProxy_DeniesAdminTierGrant(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?project_id=%d&environment_id=0", f.plainMachine, f.adminRoleID, f.projectID)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, path, nil, "AssignMachineRoleProxy (admin-tier grant)")
}

func TestSystemWriteCeiling_CreateOIDCBindingProxy_RequiresInstallWideAdminAuthority(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/machine-oidc-bindings", map[string]any{
		"machine_identity_id": f.plainMachine, "issuer": "https://ceiling-walk-preclaim.example", "subject": "preclaimed-subject",
	}, "CreateOIDCBindingProxy")
}

func TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_DeniesWithoutRolesAssign(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": f.secondAdminUserID, "role_id": f.adminRoleID,
	}, "RemoveGlobalAdminRoleGuardedProxy")
}

func TestSystemWriteCeiling_CreateSetupTokenProxy_DeniesWithoutUsersWrite(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash": "ceiling-walk-forged-hash-0000000000000000000000000000001", "purpose": "account_setup",
		"subject_email": "ceiling-walk-setup-target@example.com", "subject_user_id": f.setupTargetUserID,
		"expires_at": time.Now().Add(time.Hour),
	}, "CreateSetupTokenProxy")
}

func TestSystemWriteCeiling_RevokeAllPersonalAccessTokensForUserProxy_RequiresUsersWriteAuthority(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/users/%d/personal-access-tokens/revoke-all", f.setupTargetUserID), nil, "RevokeAllPersonalAccessTokensForUserProxy")
}

func TestSystemWriteCeiling_DeleteSessionsForUserExceptProxy_RequiresUsersWriteAuthority(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/users/%d/sessions/delete-except", f.setupTargetUserID), map[string]any{"except_session_id": 0}, "DeleteSessionsForUserExceptProxy")
}

func TestSystemWriteCeiling_CreateMachineIdentityProxy_EnforcesPrivilegeCeiling(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "ceiling-walk-forged-create", "project_id": f.projectID,
		"identity_type": core.MachineTypeService, "state": core.MachineActive,
	}, "CreateMachineIdentityProxy")
}

func TestSystemWriteCeiling_AddGroupMemberProxy_DeniesJoiningAdminTierGroupWithoutAuthority(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/groups/%d/members", f.adminTierGroupID), map[string]any{
		"user_id": f.regularUserID,
	}, "AddGroupMemberProxy (joining an admin-tier group)")
}

func TestSystemWriteCeiling_RevokeMachineIdentityCredentialProxy_RequiresRolesAssignInCredentialProject(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	requireSystemCeilingRefusedForHumanAndPermissionedNode(t, f, http.MethodPost, fmt.Sprintf("/api/v1/system/machine-credentials/%d/revoke", f.plainCredID), nil, "RevokeMachineIdentityCredentialProxy")
}

// TestSystemWriteCeiling_ApproveRiskExceptionProxy_DeniesSelfApproval is
// dimension (a): CreateRiskExceptionProxy itself is allowlisted (creation
// alone confers nothing), so f.token seeds its own exception first, then
// tries approving it.
func TestSystemWriteCeiling_ApproveRiskExceptionProxy_DeniesSelfApproval(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	createStatus, createBody := doSystemCeilingRequest(t, f, http.MethodPost, "/api/v1/system/risk-exceptions", map[string]any{
		"project_id": f.projectID, "title": "ceiling-walk-self-approve", "category": "other",
		"justification": "x", "expires_at": time.Now().Add(24 * time.Hour),
	})
	require.Equal(t, http.StatusOK, createStatus, "creation itself must succeed: %s", createBody)
	var created struct {
		Data struct {
			ID uint `json:"id"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(createBody), &created))
	status, body := doSystemCeilingRequest(t, f, http.MethodPut, fmt.Sprintf("/api/v1/system/risk-exceptions/%d/approve", created.Data.ID), map[string]any{})
	requireSystemCeilingRefused(t, status, body, "ApproveRiskExceptionProxy (self-approval)")
}

// TestSystemWriteCeiling_CreateRiskExceptionProxy_RefusesMachineActorByDesign
// is dimension (c) for BOTH risk-exception routes, and NOT the same shape as
// the human dimension above: core.CreateRiskException/ApproveRiskException
// each explicitly check actorIsMachine and deny UNCONDITIONALLY, before any
// permission or self-approval check runs -- "dual control requires a human
// approver; a machine credential cannot approve a risk exception"
// (risk_exceptions.go). This is a deliberate governance design (dual control
// means two HUMANS, not "a human plus a machine" or two machines), found
// while wiring up f.permissionedNodeToken against the self-approval test
// above: a node credential cannot even complete the CREATE precondition, so
// "self-approval" as a scenario does not apply to it at all -- the correct,
// stronger dimension-(c) assertion is that creation itself is refused.
func TestSystemWriteCeiling_CreateRiskExceptionProxy_RefusesMachineActorByDesign(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	status, body := doSystemCeilingRequestAs(t, f, f.permissionedNodeToken, http.MethodPost, "/api/v1/system/risk-exceptions", map[string]any{
		"project_id": f.projectID, "title": "ceiling-walk-machine-create-attempt", "category": "other",
		"justification": "x", "expires_at": time.Now().Add(24 * time.Hour),
	})
	requireSystemCeilingRefused(t, status, body, "CreateRiskExceptionProxy (machine actor, denied by design regardless of permission)")
}

// ── Positive controls: real in-tree callers, machine actor (Task 3) ────────────
//
// F5 (UpdateUserIfActiveStateMatchesProxy) has its own machine-actor control
// case in users_active_transition_proxy_ceiling_test.go
// (TestUpdateUserIfActiveStateMatchesProxy_MachineUsersWriteHolder_CanRewriteOtherUserEmail).
// The four below cover CLI client mode's other real callers
// (Group create/update/delete via internal/cli/group/*.go,
// UpdateInvitationProxy via internal/cli/invite/revoke.go) with a machine
// credential holding ONLY the specific narrow permission the fix now
// requires -- not core.AuthorizePrincipal's human branch, and not the full
// admin-tier bypass TestConformance_CreateGroup/UpdateGroup/DeleteGroup/
// UpdateProjectInvitation use (h.rs in remote_storage_conformance_helpers_test.go
// authenticates via createNodeToken, the "admin" role -- those conformance
// tests prove WIRE/DATA correctness, not that this branch's new narrow
// ceiling actually recognizes a real, non-admin machine credential).

func TestSystemCeilingPositiveControl_CreateGroupProxy_MachineUsersWriteHolder_Succeeds(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	status, body := doSystemCeilingRequestAs(t, f, f.usersWriteNodeToken, http.MethodPost, "/api/v1/system/groups", map[string]any{
		"name": "ceiling-walk-machine-created-group", "description": "x",
	})
	require.Equal(t, http.StatusOK, status, "a machine credential holding users.write must still be able to create a group: %s", body)
}

func TestSystemCeilingPositiveControl_UpdateGroupProxy_MachineUsersWriteHolder_Succeeds(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	status, body := doSystemCeilingRequestAs(t, f, f.usersWriteNodeToken, http.MethodPut, fmt.Sprintf("/api/v1/system/groups/%d", f.nonAdminGroupID), map[string]any{
		"name": "machine-renamed", "description": "x",
	})
	require.Equal(t, http.StatusOK, status, "a machine credential holding users.write must still be able to update a group: %s", body)
}

func TestSystemCeilingPositiveControl_DeleteGroupProxy_MachineUsersWriteHolder_Succeeds(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	status, body := doSystemCeilingRequestAs(t, f, f.usersWriteNodeToken, http.MethodDelete, fmt.Sprintf("/api/v1/system/groups/%d", f.nonAdminGroupID), nil)
	require.Equal(t, http.StatusOK, status, "a machine credential holding users.write must still be able to delete a group: %s", body)
}

// TestSystemCeilingLayeredPermission_DeleteProjectProxy_MachineSecretsDeleteHolder_Succeeds
// is the positive half of systemCeilingLayeredPermission's pair (the negative
// half -- a system.write-only node credential refused -- is proven for all
// three layered routes by the generic TestSystemGroupGateHonorsSystemWriteAcrossActorTypes
// loop). Proves the SECOND layer (RequireScopedPermission(permSecretsDelete,
// projectScope), #1657) also correctly recognizes a machine actor that DOES
// hold the needed permission -- both directions checked, not just "refused
// without it." DeleteProjectIfEmptyProxy/DeleteEnvironmentProxy share the
// identical scoped-permission middleware (#1657/#1648, same allowlist
// entries) and are not independently re-verified here.
func TestSystemCeilingLayeredPermission_DeleteProjectProxy_MachineSecretsDeleteHolder_Succeeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	ctx := context.Background()

	// This test builds its own minimal core+router+admin rather than
	// setupSystemCeilingFixtures's (that fixture's testCore isn't exposed on
	// systemCeilingFixtures, and this test needs its own dedicated, empty
	// project to delete).
	testCore := newTestCore(t)
	router, err := NewRouter(&config.Config{}, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	project, err := testCore.CreateProject(ctx, "ceiling-layered-perm-project", "empty, for delete")
	require.NoError(t, err)

	mi, err := testCore.CreateMachineIdentity(ctx, project.ID, "ceiling-layered-perm-machine", core.MachineTypeService, "", "", admin.ID, 0)
	require.NoError(t, err)

	secretsDeleteRoleName, err := identity.NewFoldedName("ceiling_layered_perm_secrets_delete")
	require.NoError(t, err)
	secretsDeleteRole, err := testCore.Storage().CreateRole(ctx, secretsDeleteRoleName, "test-only role: system.write + secrets.delete")
	require.NoError(t, err)
	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID, secretsDeleteID uint
	for _, p := range perms {
		switch p.Name {
		case "system.write":
			systemWriteID = p.ID
		case "secrets.delete":
			secretsDeleteID = p.ID
		}
	}
	require.NotZero(t, systemWriteID)
	require.NotZero(t, secretsDeleteID)
	require.NoError(t, testCore.AssignPermissionToRole(ctx, 0, secretsDeleteRole.ID, systemWriteID, false))
	require.NoError(t, testCore.AssignPermissionToRole(ctx, 0, secretsDeleteRole.ID, secretsDeleteID, false))
	// GLOBAL scope, via the storage layer directly (core.AssignMachineRole's
	// ceiling requires scope.ProjectID to match the machine's own project, so
	// it can never grant a truly global scope -- same reasoning as
	// createNodeToken/createSystemWriteOnlyNodeToken). Global is required
	// here, not project-scoped: the /system group's OWN outer gate checks
	// system.write at GLOBAL scope (RequirePermission -> ScopeGlobal), and
	// GetMachineRoleIDsAt's "project_id = 0 OR ..." query means a global
	// grant satisfies a narrower, project-scoped check too (0 matches
	// unconditionally) -- one grant clears both layers.
	require.NoError(t, testCore.Storage().AssignMachineRole(ctx, mi.ID, secretsDeleteRole.ID, coreStorage.Scope{}))
	result, err := testCore.IssueMachineToken(ctx, project.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "ceiling-layered-perm-token"})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/system/projects/%d", server.URL, project.ID), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+result.PlainToken)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode,
		"a machine credential holding system.write AND secrets.delete (scoped to the project) must be able to delete it")
}

func TestSystemCeilingPositiveControl_UpdateInvitationProxy_MachineRolesAssignHolder_Succeeds(t *testing.T) {
	f := setupSystemCeilingFixtures(t)
	status, body := doSystemCeilingRequestAs(t, f, f.rolesAssignNodeToken, http.MethodPut, fmt.Sprintf("/api/v1/system/invitations/%d", f.pendingInvitationID), map[string]any{
		"state": "revoked",
	})
	require.Equal(t, http.StatusOK, status, "a machine credential holding roles.assign must still be able to update an invitation: %s", body)
}
