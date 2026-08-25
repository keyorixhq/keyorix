// system_write_ceiling_table_test.go generalizes system_write_ceiling_test.go's
// single finding into the fix wave's acceptance criteria: every write-shaped route
// in the /api/v1/system/machine-identities, /machine-credentials, and
// /machine-oidc-bindings groups (server/http/handlers/machine_identities_proxy.go),
// exercised end-to-end through a real HTTP server + real router + real auth
// middleware, as the SAME human caller — one holding ONLY system.write, no
// admin-tier role, no node credential (see createSystemWriteOnlyToken in
// system_write_ceiling_test.go).
//
// Each row's "ceiling" column names the internal/core check that route's OWN core
// wrapper enforces and the raw proxy either does or doesn't (see
// docs/g80-raw-storage-bypass-triage.md for the full investigation each row is
// drawn from). A row is RED today if its handler is still an unguarded raw
// storage passthrough; fixing that handler (routing the specific missing check
// through, without breaking the legitimate RemoteStorage-relay wire contract —
// see e.g. machine_identities_proxy_transition_ceiling_test.go's already-fixed
// precedent) must turn it green. This file is deliberately committed red for the
// still-open rows — that red set IS the fix wave's checklist; the all-green state
// is its definition of done.
//
// Scope note: this table does not cover the group's pure GET routes (no
// escalation-relevant ceiling — the group's own system.write gate, ADR-085,
// is the only check that applies to a read) or routes already confirmed
// no-independent-ceiling / documented-exception in the triage doc (e.g.
// TouchMachineIdentityCredentialProxy, UpdateMachineIdentityProxy). Its
// RevokeMachineIdentityCredentialProxy coverage
// (RevokeMachineIdentityCredentialProxy_NodeCredential_DeniedAtGate below) is
// gate-level only: the current wire contract (DELETE-by-bare-credential-ID, no
// project/scope parameter at all) can't express a per-grant scope check
// without a RemoteStorage client-side change first — a different, harder fix
// shape than the other rows here; filed as #1551, not closed by this table.
//
// A second dimension: "Node-credential-path rows" below exercise the
// human-caller rows' SAME write routes again, but with a bare node-type
// credential holding zero role grants (f.nodeToken, createBareNodeToken)
// instead of the system.write-only human (f.token) — proving a node
// identity's type alone confers nothing (ADR-085, Accepted, 2026-08-25;
// see docs/g80-raw-storage-bypass-triage.md's "Fix status" section for the
// closure record).
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ceilingTableFixtures holds every real row this table's requests reference,
// created once per test run and shared read-only across table cases (cases that
// mutate state use their OWN dedicated fixture, never one another case depends on
// reading unmutated).
type ceilingTableFixtures struct {
	serverURL             string
	token                 string // system.write-only human caller under test
	nodeToken             string // bare node-type credential, zero role grants (createBareNodeToken)
	permissionedNodeToken string // node-type credential holding real system.write (createNodeToken) — reaches the group gate
	rolesAssignToken      string // system.write + roles.assign human caller (createSystemWriteAndRolesAssignToken)
	projectID             uint
	plainMachine          uint   // ordinary machine identity, no roles
	adminMachine          uint   // holds the admin-tier "system_admin" role at global scope
	revokedMach           uint   // machine identity already in state=revoked
	plainCredID           uint   // existing, non-revoked credential on plainMachine
	revokedCredID         uint   // existing, ALREADY-revoked credential on plainMachine
	bindingID             uint   // existing OIDC binding on plainMachine
	normalRoleID          uint   // a non-admin-tier role
	adminRoleID           uint   // system_admin's role ID
	secondAdminUserID     uint   // a SECOND global-admin user (system_admin), distinct from the bootstrap admin
	usersWriteToken       string // system.write + users.write human caller (createSystemWriteAndUsersWriteToken)
	setupTargetUserID     uint   // a real user, distinct from the caller, to target with a setup token
}

// createSystemWriteAndRolesAssignToken creates a human user holding system.write
// AND roles.assign, via a custom role well outside adminRoleNames (same rationale
// as createSystemWriteOnlyToken — an admin-tier role would bypass every
// permission check and make a test asserting on roles.assign specifically
// vacuous). Represents the legitimate direct caller RemoveGlobalAdminRoleGuardedProxy's
// fix is meant to keep working: someone who actually holds the same authority the
// human-facing DELETE /api/v1/user-roles route already requires for this operation.
func createSystemWriteAndRolesAssignToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sys_write_roles_assign", Email: "sys_write_roles_assign@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "sys_write_roles_assign@example.com", "system_viewer"))

	role, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_roles_assign", Description: "test-only role: system.write + roles.assign, nothing else",
	})
	require.NoError(t, err)

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

	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID))
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, rolesAssignID))
	require.NoError(t, c.AssignRoleToUser(ctx, "sys_write_roles_assign@example.com", "ceiling_test_system_writer_roles_assign"))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "sys_write_roles_assign", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

// createSystemWriteAndUsersWriteToken creates a human user holding system.write
// AND users.write, via a custom role well outside adminRoleNames (same rationale
// as createSystemWriteOnlyToken). Represents the legitimate direct caller
// CreateSetupTokenProxy's fix is meant to keep working: someone who actually holds
// the same authority every other admin-facing route that mints a setup token
// (POST /api/v1/users, POST /api/v1/users/{id}/resend-setup-link) already requires.
func createSystemWriteAndUsersWriteToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sys_write_users_write", Email: "sys_write_users_write@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "sys_write_users_write@example.com", "system_viewer"))

	role, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_users_write", Description: "test-only role: system.write + users.write, nothing else",
	})
	require.NoError(t, err)

	perms, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID, usersWriteID uint
	for _, p := range perms {
		switch p.Name {
		case "system.write":
			systemWriteID = p.ID
		case "users.write":
			usersWriteID = p.ID
		}
	}
	require.NotZero(t, systemWriteID, "system.write permission must already be seeded by bootstrap")
	require.NotZero(t, usersWriteID, "users.write permission must already be seeded by bootstrap")

	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID))
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, usersWriteID))
	require.NoError(t, c.AssignRoleToUser(ctx, "sys_write_users_write@example.com", "ceiling_test_system_writer_users_write"))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "sys_write_users_write", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

func setupCeilingTableFixtures(t *testing.T) ceilingTableFixtures {
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

	plainMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-plain", core.MachineTypeService, "", "", admin.ID)
	require.NoError(t, err)

	adminMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-admin-tier", core.MachineTypeService, "", "", admin.ID)
	require.NoError(t, err)
	adminRole, err := testCore.Storage().GetRoleByName(ctx, "system_admin")
	require.NoError(t, err)
	require.NoError(t, testCore.AssignMachineRole(ctx, adminMachine.ID, adminRole.ID, core.Scope{ProjectID: projectID}, admin.ID))

	revokedMachine, err := testCore.CreateMachineIdentity(ctx, projectID, "ceiling-table-revoked", core.MachineTypeService, "", "", admin.ID)
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
		MachineIdentityID: plainMachine.ID, Issuer: "https://ceiling-table.example", Subject: "table-subject", CreatedBy: admin.ID, CreatedAt: time.Now(),
	})
	require.NoError(t, err)

	normalRole, err := testCore.Storage().CreateRole(ctx, &models.Role{Name: "ceiling_table_normal_role", Description: "non-admin"})
	require.NoError(t, err)

	// A SECOND global admin, distinct from the bootstrap admin, so
	// RemoveGlobalAdminRoleGuardedProxy rows can remove ITS system_admin grant
	// without tripping the last-admin guard (the bootstrap admin survives as the
	// remaining admin either way) -- isolating the actor-authority ceiling this
	// row tests from the target-state ceiling other tests already cover.
	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ceiling-table-second-admin", Email: "ceiling-table-second-admin@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, testCore.AssignRoleToUser(ctx, "ceiling-table-second-admin@example.com", "system_admin"))
	secondAdmin, err := testCore.GetUserByEmail(ctx, "ceiling-table-second-admin@example.com")
	require.NoError(t, err)

	// A real target user, distinct from every caller above, for
	// CreateSetupTokenProxy rows to mint an account_setup token against.
	_, err = testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "ceiling-table-setup-target", Email: "ceiling-table-setup-target@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	setupTarget, err := testCore.GetUserByEmail(ctx, "ceiling-table-setup-target@example.com")
	require.NoError(t, err)

	token := createSystemWriteOnlyToken(t, testCore)
	// createNodeToken (integration_test.go) also calls createTestToken internally —
	// safe to call again here since createTestToken tolerates an already-initialized
	// system (logs and continues rather than failing).
	nodeToken := createBareNodeToken(t, testCore)
	permissionedNodeToken := createNodeToken(t, testCore)
	rolesAssignToken := createSystemWriteAndRolesAssignToken(t, testCore)
	usersWriteToken := createSystemWriteAndUsersWriteToken(t, testCore)

	return ceilingTableFixtures{
		serverURL:             server.URL,
		token:                 token,
		nodeToken:             nodeToken,
		permissionedNodeToken: permissionedNodeToken,
		rolesAssignToken:      rolesAssignToken,
		usersWriteToken:       usersWriteToken,
		projectID:             projectID,
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
	}
}

// doCeilingRequest issues method/path with body (nil for none) as the table
// fixture's system.write-only human caller and returns the status code + raw body.
func doCeilingRequest(t *testing.T, f ceilingTableFixtures, method, path string, body any) (int, string) {
	t.Helper()
	return doCeilingRequestAs(t, f, f.token, method, path, body)
}

// doCeilingRequestAs is doCeilingRequest generalized to an explicit bearer token,
// so a row can exercise the SAME route as a different caller class — e.g.
// f.nodeToken (a genuine node-credential relay) instead of f.token (the
// system.write-only human).
func doCeilingRequestAs(t *testing.T, f ceilingTableFixtures, token, method, path string, body any) (int, string) {
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

// TestSystemWriteCeiling_CreateMachineIdentityProxy_ForcesActiveState is the
// table's CreateMachineIdentityProxy row. Ceiling: core.CreateMachineIdentity
// unconditionally forces State=MachineActive on every create (machine_identities.go
// :99) — a machine identity is never born in any other state. The raw proxy
// currently persists whatever State the caller supplies verbatim. RED today: a
// system.write-only caller can mint an identity already in state "revoked" (or
// any other value), never having been active.
func TestSystemWriteCeiling_CreateMachineIdentityProxy_ForcesActiveState(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	// This case is about the state-forcing behavior, not about the privilege
	// ceiling (that's TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_
	// EnforcesPrivilegeCeiling's job) — use f.rolesAssignToken (system.write +
	// roles.assign) so the request clears the MACH-001 ceiling check that
	// CreateMachineIdentityProxy now runs, and reaches the state-forcing logic
	// under test.
	status, body := doCeilingRequestAs(t, f, f.rolesAssignToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "ceiling-table-forged-state", "project_id": f.projectID,
		"identity_type": core.MachineTypeService, "state": core.MachineRevoked,
	})
	t.Logf("CreateMachineIdentityProxy(state=%s): status=%d body=%s", core.MachineRevoked, status, body)
	require.Equal(t, http.StatusOK, status, "request itself must be accepted (a 4xx here would mean a different regression)")
	var parsed struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.Equal(t, core.MachineActive, parsed.Data.State,
		"CEILING VIOLATED: CreateMachineIdentityProxy must force State=MachineActive like core.CreateMachineIdentity does, "+
			"not persist a caller-supplied state verbatim")
}

// TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_EnforcesPrivilegeCeiling
// is the table's CreateMachineIdentityCredentialProxy row — the campaign's own
// "MOST SEVERE FINDING". Ceiling: core.IssueMachineToken calls
// requireMachinePrivilegeCeiling (MACH-001) — a non-global-admin actor cannot mint
// a credential for a machine identity that itself holds an admin-tier role,
// because that credential inherits the machine's roles (equivalent to a role
// grant). The raw proxy has no such check. RED today: a system.write-only caller
// (confirmed non-global-admin) can forge a working credential for f.adminMachine
// (holds system_admin) and authenticate as an admin-tier principal.
func TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_EnforcesPrivilegeCeiling(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": f.adminMachine,
		"token_hash":          "cccc000000000000000000000000000000000000000000000000000000000003",
		"token_prefix":        "mid_forged_admin",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(machine_identity_id=admin-tier %d): status=%d body=%s", f.adminMachine, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only, non-global-admin caller must be denied a credential for an "+
			"admin-tier machine identity (requireMachinePrivilegeCeiling, MACH-001) — got a real forged credential instead")
}

// TestSystemWriteCeiling_TransitionMachineIdentityStateProxy_RejectsIllegalTransition
// is the table's already-FIXED TransitionMachineIdentityStateProxy row (G80 Group
// A #1 — see machine_identities_proxy_transition_ceiling_test.go for the
// handler-level version of this same assertion). Included here for completeness
// of the acceptance-criteria table and to prove the fix holds at the real-server,
// real-auth layer too, not only in the direct handler-call test.
func TestSystemWriteCeiling_TransitionMachineIdentityStateProxy_RejectsIllegalTransition(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-identities/%d/transition", f.revokedMach),
		map[string]any{
			"machine_identity": map[string]any{"id": f.revokedMach, "project_id": f.projectID, "name": "x", "state": core.MachineActive},
			"from_state":       core.MachineRevoked,
		})
	t.Logf("TransitionMachineIdentityStateProxy(revoked->active): status=%d body=%s", status, body)
	require.Equal(t, http.StatusBadRequest, status,
		"revoked must stay terminal (core.IsValidMachineTransition) — a 200 here would mean this Group A fix regressed")
}

// TestSystemWriteCeiling_AssignMachineRoleProxy_DeniesAdminTierGrant is the
// table's AssignMachineRoleProxy row — already routed through core.AssignMachineRole
// (#1542), which calls requireAuthorityForRole. A non-admin caller may still grant
// a NON-admin-tier role (roles.assign's own footprint); only an admin-tier grant
// must be refused.
func TestSystemWriteCeiling_AssignMachineRoleProxy_DeniesAdminTierGrant(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?project_id=%d&environment_id=0", f.plainMachine, f.adminRoleID, f.projectID)
	status, body := doCeilingRequest(t, f, http.MethodPost, path, nil)
	t.Logf("AssignMachineRoleProxy(role=system_admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusInternalServerError, status,
		"a system.write-only caller must be refused when granting an admin-tier role (requireAuthorityForRole) — "+
			"internal/core wraps the denial as a storage error today (500), which is a real behavior gap of its own, "+
			"but the grant itself must not succeed")
}

// TestSystemWriteCeiling_AssignMachineRoleProxy_AllowsNonAdminGrant is the same
// route's companion control: a non-admin-tier grant is roles.assign's own,
// legitimate footprint and must still succeed for this caller.
func TestSystemWriteCeiling_AssignMachineRoleProxy_AllowsNonAdminGrant(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	path := fmt.Sprintf("/api/v1/system/machine-identities/%d/roles/%d?project_id=%d&environment_id=0", f.plainMachine, f.normalRoleID, f.projectID)
	status, body := doCeilingRequest(t, f, http.MethodPost, path, nil)
	t.Logf("AssignMachineRoleProxy(role=non-admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "a non-admin-tier role grant is not gated by requireAuthorityForRole and must succeed")
}

// TestSystemWriteCeiling_UpdateMachineIdentityCredentialProxy_CannotResurrectRevoked
// is the table's already-FIXED UpdateMachineIdentityCredentialProxy row (G80 Group
// A #2): the handler now only ever applies Classification from the wire body,
// never Revoked/TokenHash/ExpiresAt.
func TestSystemWriteCeiling_UpdateMachineIdentityCredentialProxy_CannotResurrectRevoked(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPut,
		fmt.Sprintf("/api/v1/system/machine-credentials/%d", f.revokedCredID),
		map[string]any{"id": f.revokedCredID, "machine_identity_id": f.plainMachine, "revoked": false, "classification": "internal"})
	t.Logf("UpdateMachineIdentityCredentialProxy(resurrect attempt): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "the update call itself must still succeed (it's a legitimate classification change)")

	status, body = doCeilingRequest(t, f, http.MethodGet, fmt.Sprintf("/api/v1/system/machine-credentials/%d", f.revokedCredID), nil)
	require.Equal(t, http.StatusOK, status)
	var parsed struct {
		Data struct {
			Revoked bool `json:"revoked"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.True(t, parsed.Data.Revoked,
		"the attempted resurrection (revoked:false in the update body) must have been silently ignored — "+
			"a real resurrection here would mean this Group A fix regressed")
}

// TestSystemWriteCeiling_CreateOIDCBindingProxy_RequiresInstallWideAdminAuthority
// is the table's CreateOIDCBindingProxy row. Ceiling: core.CreateOIDCBinding
// requires GLOBAL admin authority (requireAuthorityForRole(..., "system_admin"),
// #127) — (issuer, subject) is a global namespace, so binding one is scoped to
// what it actually claims, not merely project-scoped roles.assign. The raw proxy
// has no such check. RED today: a system.write-only caller can pre-claim any
// (issuer, subject) pair for a machine of their choosing.
func TestSystemWriteCeiling_CreateOIDCBindingProxy_RequiresInstallWideAdminAuthority(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/machine-oidc-bindings", map[string]any{
		"machine_identity_id": f.plainMachine, "issuer": "https://ceiling-table-preclaim.example", "subject": "preclaimed-subject",
	})
	t.Logf("CreateOIDCBindingProxy: status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller must be denied — binding an OIDC subject requires install-wide "+
			"admin authority (core.CreateOIDCBinding's requireAuthorityForRole check), which this caller does not hold")
}

// TestSystemWriteCeiling_DeleteOIDCBindingProxy_VerifiesOwnership is the table's
// DeleteOIDCBindingProxy row. Ceiling: core.DeleteOIDCBinding verifies the binding
// actually belongs to the named machine (machineInProject + a MachineIdentityID
// match) before deleting, and writes the machine_identity.oidc_unbound audit
// event. FIXED for a direct, non-node-credential caller (see the
// TestDeleteOIDCBindingProxy_WritesAuditEvent_S21 regression test in
// server/http/handlers, which pins the audit trail this row's own status-code
// assertion can't observe). This row is necessarily a narrower assertion than
// "denied outright" — deleting a binding you're relaying on behalf of IS
// legitimate; the fix routes through core.DeleteOIDCBinding to resolve the
// real owning machine/project rather than trusting a caller-supplied one (this
// proxy takes no project parameter at all, so there is no mismatched-project
// fixture to assert a 403/404 against here).
func TestSystemWriteCeiling_DeleteOIDCBindingProxy_VerifiesOwnership(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodDelete, fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", f.bindingID), nil)
	t.Logf("DeleteOIDCBindingProxy: status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status, "the delete itself is expected to succeed for a binding that IS legitimately owned by its machine")
}

// TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_DeniesWithoutRolesAssign
// is the table's RemoveGlobalAdminRoleGuardedProxy row (G80 documented-exception
// re-verification sweep, 2026-08-25). Ceiling: the human-facing equivalent
// (DELETE /api/v1/user-roles) requires roles.assign AT THE TARGET SCOPE
// (router.go's user-roles route, #342); this proxy's OWN gate was only
// system.write (RequireNodeCredentialOrPermission), materially weaker and, per
// auth_bootstrap.go's own doc, granted for unrelated reasons (audit checkpoints,
// legal holds, SoD policies). FIXED: a direct (non-node-credential) caller now
// needs roles.assign at global scope. RED before the fix: f.token (system.write,
// no roles.assign) could strip f.secondAdminUserID's system_admin grant outright.
func TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_DeniesWithoutRolesAssign(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": f.secondAdminUserID, "role_id": f.adminRoleID,
	})
	t.Logf("RemoveGlobalAdminRoleGuardedProxy(system.write only, target=second-admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller with no roles.assign must be denied removal of another "+
			"user's global-admin role grant — the atomicity of the last-admin guard was never the gap; the missing "+
			"actor-authority check was")
}

// TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_AllowsWithRolesAssign is
// this row's companion control: a caller who legitimately holds roles.assign (the
// SAME authority the human-facing route already requires) must still be able to
// perform this operation — the fix must not turn into a blanket denial.
func TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_AllowsWithRolesAssign(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.rolesAssignToken, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": f.secondAdminUserID, "role_id": f.adminRoleID,
	})
	t.Logf("RemoveGlobalAdminRoleGuardedProxy(roles.assign holder, target=second-admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"a caller who genuinely holds roles.assign at global scope must still be able to remove another admin's "+
			"grant — the last-admin guard passes here because the bootstrap admin survives as the remaining admin")
}

// TestSystemWriteCeiling_CreateSetupTokenProxy_DeniesWithoutUsersWrite is the
// table's CreateSetupTokenProxy row (G80 documented-exception re-verification
// sweep, 2026-08-25). Ceiling: minting a setup token for user X is equivalent to
// taking control of X -- every other admin-facing route that mints one
// (POST /api/v1/users, POST /api/v1/users/{id}/resend-setup-link) requires
// users.write. FIXED: a direct (non-node-credential) caller now needs users.write
// too. RED before the fix: f.token (system.write, no users.write) could mint a
// fully-valid, immediately-redeemable account_setup token for f.setupTargetUserID.
func TestSystemWriteCeiling_CreateSetupTokenProxy_DeniesWithoutUsersWrite(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequest(t, f, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash":      "ceiling-table-forged-hash-0000000000000000000000000000001",
		"purpose":         "account_setup",
		"subject_email":   "ceiling-table-setup-target@example.com",
		"subject_user_id": f.setupTargetUserID,
		"expires_at":      time.Now().Add(time.Hour),
	})
	t.Logf("CreateSetupTokenProxy(system.write only, target=setup-target): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"CEILING VIOLATED: a system.write-only caller with no users.write must be denied minting a setup token "+
			"for another user — the internal invitation/user cross-reference check was never the gap; the "+
			"missing actor-authority check was")
}

// TestSystemWriteCeiling_CreateSetupTokenProxy_AllowsWithUsersWrite is this row's
// companion control: a caller who legitimately holds users.write (the SAME
// authority every other route that mints a setup token already requires) must
// still be able to perform this operation.
func TestSystemWriteCeiling_CreateSetupTokenProxy_AllowsWithUsersWrite(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.usersWriteToken, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash":      "ceiling-table-legit-hash-00000000000000000000000000000001",
		"purpose":         "account_setup",
		"subject_email":   "ceiling-table-setup-target@example.com",
		"subject_user_id": f.setupTargetUserID,
		"expires_at":      time.Now().Add(time.Hour),
	})
	t.Logf("CreateSetupTokenProxy(users.write holder, target=setup-target): status=%d body=%s", status, body)
	require.Equal(t, http.StatusOK, status,
		"a caller who genuinely holds users.write must still be able to mint a setup token for another user")
}

// TestSystemWriteCeiling_CreateSetupTokenProxy_CreatedByIsAlwaysCaller closes a
// gap the two rows above can't see: neither exercises whether
// model.CreatedBy = userCtx.PrincipalID() (setup_tokens_proxy.go) is
// load-bearing, since the wire body's own created_by is simply never read by
// either. A genuine users.write holder forging created_by to a DIFFERENT real
// user (secondAdminUserID) must still have the persisted, returned record
// attribute the token to themselves, not the forged identity.
func TestSystemWriteCeiling_CreateSetupTokenProxy_CreatedByIsAlwaysCaller(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.usersWriteToken, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash":      "ceiling-table-createdby-hash-0000000000000000000000000001",
		"purpose":         "account_setup",
		"subject_email":   "ceiling-table-setup-target@example.com",
		"subject_user_id": f.setupTargetUserID,
		"created_by":      f.secondAdminUserID,
		"expires_at":      time.Now().Add(time.Hour),
	})
	t.Logf("CreateSetupTokenProxy(users.write holder, created_by forged to a different real user %d): status=%d body=%s", f.secondAdminUserID, status, body)
	require.Equal(t, http.StatusOK, status)

	var parsed struct {
		Data struct {
			CreatedBy uint `json:"created_by"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.NotEqual(t, f.secondAdminUserID, parsed.Data.CreatedBy, "created_by must not be the forged user ID")
	require.NotZero(t, parsed.Data.CreatedBy, "created_by must be a real, attributable caller")
}

// TestSystemWriteCeiling_CreateSetupTokenProxy_NodeCredential_StillBypassesAuthorityCheck
// pins the CLOSED gap: ADR-085 (Accepted, 2026-08-25) removed
// isNodeCredentialRequest's unconditional-passthrough branch AND the
// node-credential OR-arm from the /system group's own gate
// (RequireNodeCredentialOrPermission → RequirePermission(system.write),
// router.go). f.nodeToken (createBareNodeToken) holds no role grant at all,
// so it is refused a layer earlier than the human-caller row above: at the
// group's blanket system.write gate, never reaching this route's own
// users.write check at all.
func TestSystemWriteCeiling_CreateSetupTokenProxy_NodeCredential_StillBypassesAuthorityCheck(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/setup-tokens", map[string]any{
		"token_hash":      "ceiling-table-node-hash-000000000000000000000000000000001",
		"purpose":         "account_setup",
		"subject_email":   "ceiling-table-setup-target@example.com",
		"subject_user_id": f.setupTargetUserID,
		"expires_at":      time.Now().Add(time.Hour),
	})
	t.Logf("CreateSetupTokenProxy(node credential, target=setup-target): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential with no role grant must not mint a setup token for another user")
}

// ── Node-credential-path rows ────────────────────────────────────────────────
//
// The rows below exercise the SAME routes above, but with f.nodeToken (a
// genuine node-type machine credential holding NO role grant —
// createBareNodeToken, integration_test.go) instead of f.token (the
// system.write-only human). ADR-085 (Accepted, 2026-08-25) found the
// "downstream node relay" topology these routes' isNodeCredentialRequest(r)
// branches existed to serve cannot exist in this codebase at all (ADR-083's
// validateRemoteStorageNotServer rejects storage.type: remote for any server
// process), and that a liveness sweep found no live caller for the branch
// anyway (createNodeToken is test-only in every reference; no deployment
// artifact provisions a node credential for runtime use). The branches are
// deleted; a node credential is now authorized the SAME way any other caller
// is, via a real role grant it either has or doesn't. These rows use a BARE
// node credential (zero role grants) specifically to pin that a node
// identity's type alone confers nothing.

// TestSystemWriteCeiling_CreateMachineIdentityProxy_NodeCredential_AlsoForcesActiveState
// uses f.permissionedNodeToken (createNodeToken — a node-type credential that
// DOES hold system.write, unlike every other row in this section) rather than
// the bare f.nodeToken: this route's whole point is that
// core.CreateMachineIdentity has no actor-authority check at all (only
// State/IdentityType/Classification validation) for ANY caller who reaches
// it, and a bare node credential can no longer reach it at all (denied at the
// group's own system.write gate, ADR-085) — proving that would just repeat
// every other row in this section, not this route's own, different property.
func TestSystemWriteCeiling_CreateMachineIdentityProxy_NodeCredential_AlsoForcesActiveState(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.permissionedNodeToken, http.MethodPost, "/api/v1/system/machine-identities", map[string]any{
		"name": "ceiling-table-node-create", "project_id": f.projectID,
		"identity_type": core.MachineTypeService, "state": core.MachineRevoked,
	})
	t.Logf("CreateMachineIdentityProxy(permissioned node credential, state=%s): status=%d body=%s", core.MachineRevoked, status, body)
	require.Equal(t, http.StatusOK, status, "no actor-authority check exists for either caller class on this route")
	var parsed struct {
		Data struct {
			State string `json:"state"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
	require.Equal(t, core.MachineActive, parsed.Data.State, "same forced-active behavior as the human-caller row — no caller-class difference here")
}

// TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_NodeCredential_StillBypassesPrivilegeCeiling
// pins the CLOSED gap: with isNodeCredentialRequest's branch AND the
// node-credential OR-arm both removed (ADR-085), a bare node credential is
// refused at the /system group's own system.write gate before ever reaching
// requireMachinePrivilegeCeiling — it can no longer forge a credential for
// f.adminMachine (holds system_admin). The campaign's original "MOST SEVERE
// FINDING" (#1552) is closed for every caller class, not just the direct
// human one.
func TestSystemWriteCeiling_CreateMachineIdentityCredentialProxy_NodeCredential_StillBypassesPrivilegeCeiling(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/machine-credentials", map[string]any{
		"machine_identity_id": f.adminMachine,
		"token_hash":          "dddd000000000000000000000000000000000000000000000000000000000004",
		"token_prefix":        "mid_forged_admin_node",
	})
	t.Logf("CreateMachineIdentityCredentialProxy(node credential, machine_identity_id=admin-tier %d): status=%d body=%s", f.adminMachine, status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential must not forge a credential for an admin-tier machine identity")
}

// TestSystemWriteCeiling_CreateOIDCBindingProxy_NodeCredential_StillBypassesAdminAuthority
// pins the CLOSED gap: with isNodeCredentialRequest's branch AND the
// node-credential OR-arm both removed (ADR-085), a bare node credential is
// refused at the /system group's own system.write gate before ever reaching
// requireAuthorityForRole("system_admin") — it can no longer pre-claim an
// OIDC (issuer, subject) pair. Even a node credential that DID hold
// system.write couldn't pass that check either: it resolves authority via
// scopedRoleIDs (internal/core/authz.go), which walks only a USER's direct
// and group role grants — no machine actor, bare or admin-tier, can ever
// satisfy it (see remote_storage_machine_identities_test.go's
// OIDCBindingCreateGetListDelete_RealServer for that finding against a
// genuinely-permissioned machine).
func TestSystemWriteCeiling_CreateOIDCBindingProxy_NodeCredential_StillBypassesAdminAuthority(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/machine-oidc-bindings", map[string]any{
		"machine_identity_id": f.plainMachine, "issuer": "https://ceiling-table-node-preclaim.example", "subject": "node-preclaimed-subject",
	})
	t.Logf("CreateOIDCBindingProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a node credential must not pre-claim an OIDC (issuer, subject) pair with no install-wide admin-authority check")
}

// TestSystemWriteCeiling_DeleteOIDCBindingProxy_NodeCredential_StillBypassesOwnershipCheck
// pins the CLOSED gap: with isNodeCredentialRequest's branch removed, a bare
// node credential is refused at the /system group's own system.write gate
// before ever reaching core.DeleteOIDCBinding — unlike the direct-caller row
// above (which DOES hold system.write and so still succeeds:
// core.DeleteOIDCBinding itself has no caller-authority check beyond a
// binding-belongs-to-this-machine identity check, which trivially holds since
// the machine is derived FROM the binding being deleted; the fix there was
// adding the audit event the raw passthrough skipped, not an authority
// ceiling). A bare node credential never gets that far.
func TestSystemWriteCeiling_DeleteOIDCBindingProxy_NodeCredential_StillBypassesOwnershipCheck(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodDelete, fmt.Sprintf("/api/v1/system/machine-oidc-bindings/%d", f.bindingID), nil)
	t.Logf("DeleteOIDCBindingProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential must not reach DeleteOIDCBinding at all")
}

// TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_NodeCredential_StillBypassesAuthorityCheck
// pins the CLOSED gap: with isNodeCredentialRequest's branch AND the
// node-credential OR-arm both removed (ADR-085), a bare node credential is
// refused at the /system group's own system.write gate before ever reaching
// the roles.assign-at-global-scope check — it can no longer strip a named
// admin's global-admin role.
func TestSystemWriteCeiling_RemoveGlobalAdminRoleGuardedProxy_NodeCredential_StillBypassesAuthorityCheck(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/rbac/global-admin-role/remove-guarded", map[string]any{
		"user_id": f.secondAdminUserID, "role_id": f.adminRoleID,
	})
	t.Logf("RemoveGlobalAdminRoleGuardedProxy(node credential, target=second-admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential must not strip a named admin's global-admin role grant")
}

// TestSystemWriteCeiling_AssignRoleWithExpiryProxy_NodeCredential_DeniedAtGate
// closes #1552, the campaign's original "MOST SEVERE FINDING" (a system.write
// caller granting itself/anyone the system_admin role via the raw
// storage.AssignRoleWithExpiry passthrough), specifically for the
// node-credential axis: a bare node credential attempting to self-grant
// system_admin is refused at the /system group's own system.write gate
// (ADR-085), never reaching AssignRoleWithExpiryProxy's own
// requireGranterHoldsRolePermissions check at all.
func TestSystemWriteCeiling_AssignRoleWithExpiryProxy_NodeCredential_DeniedAtGate(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, "/api/v1/system/rbac/assign-role-with-expiry", map[string]any{
		"user_id": f.secondAdminUserID, "role_id": f.adminRoleID, "expires_at": time.Now().Add(time.Hour),
	})
	t.Logf("AssignRoleWithExpiryProxy(node credential, role=system_admin): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential must not reach AssignRoleWithExpiryProxy at all")
}

// TestSystemWriteCeiling_RevokeMachineIdentityCredentialProxy_NodeCredential_DeniedAtGate
// closes #1551's node-credential axis: RevokeMachineIdentityCredentialProxy
// itself is STILL an unconditional raw storage.RevokeMachineIdentityCredential
// passthrough with no caller-authority or project-scope check at all — that
// deeper gap (any system.write holder can revoke any credential cross-tenant)
// is unchanged and remains filed as #1551 (the wire contract, a bare
// credential ID with no scope parameter, can't express a scope check without
// a RemoteStorage client-side change first). What ADR-085 closes is narrower
// but real: a bare node credential can no longer reach the handler AT ALL,
// refused at the /system group's own system.write gate.
func TestSystemWriteCeiling_RevokeMachineIdentityCredentialProxy_NodeCredential_DeniedAtGate(t *testing.T) {
	f := setupCeilingTableFixtures(t)
	status, body := doCeilingRequestAs(t, f, f.nodeToken, http.MethodPost, fmt.Sprintf("/api/v1/system/machine-credentials/%d/revoke", f.plainCredID), nil)
	t.Logf("RevokeMachineIdentityCredentialProxy(node credential): status=%d body=%s", status, body)
	require.Equal(t, http.StatusForbidden, status,
		"ADR-085: a bare node credential must not reach RevokeMachineIdentityCredentialProxy at all")
}
