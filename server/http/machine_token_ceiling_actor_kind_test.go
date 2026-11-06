// machine_token_ceiling_actor_kind_test.go — end-to-end HTTP regression for the
// authzdiff known-03 finding (internal historical name D3): POST
// /api/v1/projects/{id}/machine-identities/{machineId}/tokens is gated by
// RequireScopedPermission(roles.assign) -- already actor-kind-aware, already admits a
// machine actor -- but the handler's call into core.IssueMachineToken used to hardcode
// the AUTHORIZING principal as (ActorTypeUser, actor.UserID), and actor.UserID is
// always 0 for a machine caller (ADR-030). So a machine actor that the route's own
// gate had just admitted was then refused by the inner MACH-001 ceiling check it sits
// behind, unconditionally, regardless of its real authority.
//
// This file drives the real HTTP router with a real, issued machine bearer token (not
// a hand-built UserContext), exactly like secrets_machine_permission_test.go, through
// the full stack: auth middleware -> route-scoped permission gate -> handler -> core.
package http

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
)

// mtCeilingFixture bootstraps a full-schema test core + router, an admin, and a
// project. It issues the ACTOR machine (granted builtin "project_admin", which
// explicitly bundles roles.assign in its own RolePermission rows -- a machine
// principal never consults the ADR-084 admin-bypass flag project_admin also
// carries; see AuthorizePrincipal's doc comment -- at the project scope) a real
// bearer token, and creates a TARGET machine in the same project, optionally also granted
// targetRoleName (empty = no role, i.e. not admin-tier), for the actor to mint a
// token for. Returns the server, the actor's token, the project ID and the target
// machine's ID.
func mtCeilingFixture(t *testing.T, targetRoleName string) (*httptest.Server, string, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)
	c := newFullSchemaTestCore(t)
	ctx := context.Background()

	c.SetBootstrapToken("test-bootstrap-token")
	_, err := c.BootstrapSystem(ctx, &core.BootstrapRequest{
		Username: "testadmin", Email: "testadmin@example.com",
		Password: "TestPassword123!", Token: "test-bootstrap-token",
	})
	require.NoError(t, err)
	admin, err := c.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)

	projects, err := c.ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	proj := projects[0]

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	roleIDByName := map[string]uint{}
	for _, r := range roles {
		roleIDByName[r.Name] = r.ID
	}
	require.NotZero(t, roleIDByName["project_admin"], "builtin role project_admin must exist")

	actorMachine, err := c.CreateMachineIdentity(ctx, proj.ID, "mtc-ceiling-actor", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	// The actor holds roles.assign at the project (what the route's own outer gate,
	// RequireScopedPermission(roles.assign), already requires to reach the handler
	// at all) -- proving the ceiling's own decision, not the route gate's.
	require.NoError(t, c.AssignMachineRole(ctx, actorMachine.ID, roleIDByName["project_admin"], core.Scope{ProjectID: proj.ID}, admin.ID, false))

	target, err := c.CreateMachineIdentity(ctx, proj.ID, "mtc-target", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	if targetRoleName != "" {
		require.NotZero(t, roleIDByName[targetRoleName], "builtin role %s must exist", targetRoleName)
		require.NoError(t, c.AssignMachineRole(ctx, target.ID, roleIDByName[targetRoleName], core.Scope{ProjectID: proj.ID}, admin.ID, false))
	}

	router, err := NewRouter(&config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"}}}, c)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// The actor's own token is minted by the human admin through the same HTTP
	// route, not by calling core.IssueMachineToken directly, so this file compiles
	// against the pre-fix signature too and its red/green proof is a real 500/201
	// (and 500/403) difference, not a compile error.
	const adminSession = "mtc-ceiling-admin-session"
	_, err = c.Storage().CreateSession(ctx, &models.Session{UserID: admin.ID, SessionToken: adminSession})
	require.NoError(t, err)
	status, body := doMachineRequest(t, srv, adminSession, "POST", machineTokensPath(proj.ID, actorMachine.ID), []byte(`{"name":"mtc-actor-token"}`))
	require.Equal(t, 201, status, "admin must be able to mint the actor machine's token: %s", body)
	var minted struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal([]byte(body), &minted))
	require.NotEmpty(t, minted.Data.Token)
	return srv, minted.Data.Token, proj.ID, target.ID
}

func machineTokensPath(projectID, machineID uint) string {
	return "/api/v1/projects/" + strconv.FormatUint(uint64(projectID), 10) +
		"/machine-identities/" + strconv.FormatUint(uint64(machineID), 10) + "/tokens"
}

// TestIssueMachineTokenHTTP_MachineActorHoldingRolesAssign_Succeeds is the primary
// known-03/D3 regression: a machine actor holding roles.assign at the target's
// project -- already let through the route's own RequireScopedPermission gate --
// must now succeed at minting a token for an unprivileged target machine. Before the
// fix this was an unconditional 500 (MACH-001 ceiling evaluating "user 0", wrapped by
// the handler's un-mapped-sentinel default branch): the route gate admitted the
// actor, the inner ceiling check then refused it anyway.
func TestIssueMachineTokenHTTP_MachineActorHoldingRolesAssign_Succeeds(t *testing.T) {
	srv, actorToken, projID, targetID := mtCeilingFixture(t, "" /* target holds no role: not admin-tier */)

	status, body := doMachineRequest(t, srv, actorToken, "POST", machineTokensPath(projID, targetID), []byte(`{"name":"issued-by-machine-actor"}`))
	require.Equal(t, 201, status, "machine actor holding roles.assign must be able to issue a token for an unprivileged target: %s", body)
}

// TestIssueMachineTokenHTTP_AdminTierTarget_MachineActorStillDenied is the control:
// the D3 fix corrects WHICH principal the ceiling evaluates, it does not remove the
// ceiling. The actor here holds roles.assign (same as the success case above, and
// enough to clear the route's own outer gate) but the TARGET machine itself holds
// an admin-tier role (project_admin, structurally flagged via ADR-084's
// BypassesPermissionChecks) -- so requireMachinePrivilegeCeiling's admin-tier branch
// applies, and a machine actor is NEVER treated as a global admin there (ADR-030/
// MACH-001), regardless of what it otherwise holds. Must still be denied.
//
// Also proves the handler's status-code mapping fix (errors.Is(err,
// core.ErrPermissionDenied) -> 403): before that fix this returned 500, since none
// of the switch's substring arms match ErrMachinePrivilegeCeilingDenied's wrapped
// text.
func TestIssueMachineTokenHTTP_AdminTierTarget_MachineActorStillDenied(t *testing.T) {
	srv, actorToken, projID, targetID := mtCeilingFixture(t, "project_admin" /* target IS admin-tier */)

	status, body := doMachineRequest(t, srv, actorToken, "POST", machineTokensPath(projID, targetID), []byte(`{"name":"should-be-denied"}`))
	require.Equal(t, 403, status, "a machine actor must never be treated as a global admin, so it must be denied minting a token for an admin-tier target (403, not the old 500): %s", body)
}
