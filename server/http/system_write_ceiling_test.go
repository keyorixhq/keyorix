// system_write_ceiling_test.go answers, empirically against a real HTTP server, a
// question the G80 raw-storage-bypass triage (docs/g80-raw-storage-bypass-triage.md)
// depended on but never tested directly: is the /system RemoteStorage-sync proxy
// tier (server/http/router.go's `r.Route("/system", ...)`, gated by
// RequirePermission(permSystemWrite) — server/middleware/auth.go) reachable by a
// HUMAN principal holding ONLY the system.write permission — no admin-tier role?
//
// At the time this test was written the group was gated by
// RequireNodeCredentialOrPermission (server/middleware/node_credential.go): a
// node-type machine credential OR the existing system.write permission. ADR-085
// (Accepted, 2026-08-25) removed the node-credential arm entirely — the group now
// requires plain system.write for every caller, node-typed or not — but the
// question this test answers (does a system.write-only human, no admin-tier role,
// reach this group) is unaffected by that removal, and ADR-085 independently
// confirms system.write is intentionally grantable to a narrow, documented custom
// role (audit checkpoints, legal holds, risk exceptions, SoD policies, admin job
// triggers) — not admin-only. This test proves reachability end-to-end through the
// real router + real auth + a real RBAC-gated storage backend, and
// system_write_ceiling_table_test.go builds on the SAME harness to cover the rest
// of the machine-identity/credential/OIDC-binding proxy surface.
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createSystemWriteOnlyToken creates a human user holding ONLY the system.write
// permission, via a custom role named well outside adminRoleNames
// (internal/core/authz.go: "super_admin"/"admin"/"system_admin"/"project_admin" all
// unconditionally bypass every permission check, which would make this test
// vacuously pass). The auto-assigned system_viewer baseline (system.read only, see
// createNoPermissionToken in deployment_disclosure_family_test.go) is stripped so
// system.write is the ONLY permission this principal holds anywhere, at any scope.
func createSystemWriteOnlyToken(t *testing.T, c *core.KeyorixCore) string {
	t.Helper()
	ctx := context.Background()

	_, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sys_write_only", Email: "sys_write_only@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "sys_write_only@example.com", "system_viewer"))

	role, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer", Description: "test-only role: system.write and nothing else",
	})
	require.NoError(t, err)

	perms, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	var systemWriteID uint
	for _, p := range perms {
		if p.Name == "system.write" {
			systemWriteID = p.ID
			break
		}
	}
	require.NotZero(t, systemWriteID, "system.write permission must already be seeded by bootstrap")

	// actorID 0 = the system pseudo-actor (skips AssignPermissionToRole's #169
	// self-permission-holding check, which a fixture setup step has no actor for).
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, role.ID, systemWriteID, false))
	require.NoError(t, c.AssignRoleToUser(ctx, "sys_write_only@example.com", "ceiling_test_system_writer"))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "sys_write_only", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

func TestSystemWriteOnlyCeiling_RealServer(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	cfg := &config.Config{}
	testCore := newTestCore(t)
	router, err := NewRouter(cfg, testCore)
	require.NoError(t, err)
	server := httptest.NewServer(router)
	defer server.Close()

	ctx := context.Background()
	createTestToken(t, testCore) // bootstrap admin + seed roles/permissions (incl. system.write)
	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects, "createTestToken must have seeded a default project")

	// A real target machine identity for the proxy call to attach a credential to —
	// created by the admin, exactly as a real deployment would have one.
	targetMI, err := testCore.CreateMachineIdentity(ctx, projects[0].ID,
		"ceiling-test-target", core.MachineTypeService, "target for the ceiling test", "", admin.ID)
	require.NoError(t, err)

	token := createSystemWriteOnlyToken(t, testCore)
	// Task 1's caller needs roles.assign too now that CreateMachineIdentityCredentialProxy
	// runs core.RequireMachinePrivilegeCeiling (MACH-001) unconditionally, not only
	// system.write — createSystemWriteAndRolesAssignToken (system_write_ceiling_table_test.go,
	// same package) grants exactly that, at global scope, via a custom role outside
	// adminRoleNames (so this stays a genuine roles.assign-holder, not an admin-tier bypass).
	rolesAssignToken := createSystemWriteAndRolesAssignToken(t, testCore)
	client := &http.Client{Timeout: 10 * time.Second}

	// --- Task 1: the finding under test ---
	// CreateMachineIdentityCredentialProxy performs no PER-ROUTE authorization check
	// of its own beyond core.RequireMachinePrivilegeCeiling (MACH-001, added by the
	// independent-verification fix): the caller must hold roles.assign at the target
	// project's scope (or the target must be admin-tier, which forces global-admin
	// instead — not the case here, targetMI is an ordinary machine). system.write
	// alone is no longer sufficient to reach a successful mint; system.write +
	// roles.assign is.
	reqBody, err := json.Marshal(map[string]any{
		"machine_identity_id": targetMI.ID,
		"token_hash":          "0000000000000000000000000000000000000000000000000000000000000001",
		"token_prefix":        "mid_ceiling_test",
	})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/system/machine-credentials", bytes.NewReader(reqBody))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+rolesAssignToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var respBuf bytes.Buffer
	_, err = respBuf.ReadFrom(resp.Body)
	require.NoError(t, err)
	t.Logf("Task 1 — POST /api/v1/system/machine-credentials as a system.write+roles.assign human (no admin role, no node credential): status=%d body=%s",
		resp.StatusCode, respBuf.String())

	// --- Task 2 (control): the ORIGINAL system.write-ONLY caller (no roles.assign) against
	// a route with its ceiling intact ---
	// IssueMachineToken (server/http/handlers/machine_identities.go — the direct/
	// human-facing endpoint backing CreateMachineIdentityCredentialProxy's CLI
	// equivalent) requires roles.assign in the TARGET project's scope
	// (RequireScopedPermission(permRolesAssign, projectScope), router.go). This caller
	// holds neither roles.assign nor any project-scoped role at all — a 403 here proves
	// the harness genuinely constructed a scoped, non-admin, non-roles.assign caller (not
	// one silently treated as admin everywhere), which is what makes Task 1's roles.assign
	// grant meaningful (an ADDED authority, not a fixture that was already omnipotent).
	controlBody, err := json.Marshal(map[string]any{"name": "ceiling-test-control-token"})
	require.NoError(t, err)
	controlURL := fmt.Sprintf("%s/api/v1/projects/%d/machine-identities/%d/tokens", server.URL, projects[0].ID, targetMI.ID)
	controlReq, err := http.NewRequest(http.MethodPost, controlURL, bytes.NewReader(controlBody))
	require.NoError(t, err)
	controlReq.Header.Set("Authorization", "Bearer "+token)
	controlReq.Header.Set("Content-Type", "application/json")
	controlResp, err := client.Do(controlReq)
	require.NoError(t, err)
	defer func() { _ = controlResp.Body.Close() }()
	var controlBuf bytes.Buffer
	_, err = controlBuf.ReadFrom(controlResp.Body)
	require.NoError(t, err)
	t.Logf("Control — POST %s as the ORIGINAL system.write-only human (no roles.assign): status=%d body=%s",
		controlURL, controlResp.StatusCode, controlBuf.String())

	// Assertions follow the empirically observed behavior of the group's own gate
	// (RequirePermission(permSystemWrite), server/middleware/auth.go, since ADR-085
	// removed the RequireNodeCredentialOrPermission arm this test was originally
	// written against): it calls AuthorizePrincipal(ctx, actorKind, principalID,
	// "system.write", core.Scope{}) with NO further per-route check, so a
	// system.write holder — human or machine, admin or not — reaches the handler.
	// CreateMachineIdentityCredentialProxy itself now ALSO runs
	// core.RequireMachinePrivilegeCeiling (MACH-001, independent-verification fix,
	// 2026-08-25) unconditionally: the caller must additionally hold roles.assign in
	// the target project's scope (targetMI is an ordinary, non-admin-tier machine, so
	// the admin-tier-target branch of the ceiling doesn't apply here — that case is
	// covered by system_write_ceiling_table_test.go's EnforcesPrivilegeCeiling/
	// StillBypassesPrivilegeCeiling rows). Hence Task 1 uses rolesAssignToken
	// (system.write + roles.assign) rather than the plain system.write-only token.
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"a system.write+roles.assign human is expected to reach CreateMachineIdentityCredentialProxy for a "+
			"non-admin-tier target machine: the group's own gate requires only system.write, and "+
			"core.RequireMachinePrivilegeCeiling is satisfied by the caller's roles.assign grant at the "+
			"target project scope (writeRemoteAPISuccess never calls WriteHeader, so success is 200, not 201)")
	assert.True(t, respBuf.Len() > 0 && bytes.Contains(respBuf.Bytes(), []byte(`"success":true`)),
		"expected a real created-credential response body, not just a 200 status")
	assert.Equal(t, http.StatusForbidden, controlResp.StatusCode,
		"the SAME caller must be denied at the ceiling-intact direct endpoint (requires roles.assign "+
			"in the target project scope, which this caller does not hold) — otherwise the harness is "+
			"not proving what it claims to")
}
