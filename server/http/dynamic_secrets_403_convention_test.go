// dynamic_secrets_403_convention_test.go — #1645/ADR-096: live proof that
// dynamic-secret config/lease routes now follow the house 403-for-both
// anti-enumeration convention (via RequireScopedPermission +
// ScopeFromDynamicSecretConfigParam/ScopeFromDynamicSecretLeaseParam,
// router.go), not the old Convention B (uniform 404 regardless of caller
// privilege) loadAuthorizedConfig/loadAuthorizedLease used to implement.
//
// This can only be demonstrated through the real router + middleware chain
// -- the authorization decision no longer lives in the handler at all
// (server/http/handlers/dynamic_secrets.go's loadConfig/loadLease just
// re-fetch an already-authorized row), so a handler-level unit test cannot
// exercise it.
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
	"github.com/keyorixhq/keyorix/internal/identity"
)

type dynSecret403Fixture struct {
	serverURL    string
	core         *core.KeyorixCore
	configID     uint
	limitedToken string // secrets.read+write in a DIFFERENT project, zero access to configID
	adminToken   string // global admin -- the narrow real-404 exception
}

func newDynSecret403Fixture(t *testing.T) *dynSecret403Fixture {
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
	adminToken := createTestToken(t, testCore) // bootstraps admin + project A + default env

	admin, err := testCore.GetUserByEmail(ctx, "testadmin@example.com")
	require.NoError(t, err)
	projects, err := testCore.Storage().ListProjects(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, projects)
	projA := projects[0]
	envsA, err := testCore.Storage().ListEnvironments(ctx)
	require.NoError(t, err)
	var envA uint
	for _, e := range envsA {
		if e.ProjectID == projA.ID {
			envA = e.ID
			break
		}
	}
	require.NotZero(t, envA)

	dsCfg, err := testCore.CreateDynamicSecretConfig(ctx, &core.CreateDynamicSecretConfigRequest{
		Name: "probe-target", ProjectID: projA.ID, EnvironmentID: envA,
		BackendType: "postgres", AdminDSN: "postgres://admin@db/x",
		DefaultTTLSeconds: 300, MaxTTLSeconds: 3600, MaxActiveLeases: 10,
		CreatedBy: "testadmin", ActorID: admin.ID,
	})
	require.NoError(t, err)

	// Project B: the "limited" attacker's own turf -- entirely separate from
	// project A, where the target config lives.
	projB, err := testCore.CreateProject(ctx, "projB", "attacker project")
	require.NoError(t, err)

	perms, err := testCore.ListPermissions(ctx)
	require.NoError(t, err)
	var readID, writeID uint
	for _, p := range perms {
		if p.Name == "secrets.read" {
			readID = p.ID
		}
		if p.Name == "secrets.write" {
			writeID = p.ID
		}
	}
	require.NotZero(t, readID)
	require.NotZero(t, writeID)
	foldedRoleName, err := identity.NewFoldedName("limited-403-conv-role")
	require.NoError(t, err)
	role, err := testCore.Storage().CreateRole(ctx, foldedRoleName, "limited")
	require.NoError(t, err)
	require.NoError(t, testCore.AssignPermissionToRole(ctx, admin.ID, role.ID, readID, false))
	require.NoError(t, testCore.AssignPermissionToRole(ctx, admin.ID, role.ID, writeID, false))

	limited, err := testCore.CreateUser(ctx, &core.CreateUserRequest{
		Username: "limited403", Email: "limited403@example.com", Password: "Xk9#mQ7zLp2!vR4t",
	})
	require.NoError(t, err)
	require.NoError(t, testCore.Storage().AssignRole(ctx, limited.ID, role.ID, core.Scope{ProjectID: projB.ID}))

	session, _, err := testCore.Login(ctx, &core.LoginRequest{Username: "limited403", Password: "Xk9#mQ7zLp2!vR4t"})
	require.NoError(t, err)

	return &dynSecret403Fixture{
		serverURL:    server.URL,
		core:         testCore,
		configID:     dsCfg.ID,
		limitedToken: session.SessionToken,
		adminToken:   adminToken,
	}
}

func (f *dynSecret403Fixture) get(t *testing.T, token string, id uint) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/dynamic-secrets/configs/%d", f.serverURL, id), nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp.StatusCode, buf.String()
}

// TestDynamicSecretConfig_403ForBoth_UnprivilegedCallerCannotDistinguish is the
// core property #1645/ADR-096 requires: a caller with no access anywhere near
// the target config gets the IDENTICAL response for a real config they can't
// see and a config ID that doesn't exist at all.
func TestDynamicSecretConfig_403ForBoth_UnprivilegedCallerCannotDistinguish(t *testing.T) {
	f := newDynSecret403Fixture(t)

	statusReal, bodyReal := f.get(t, f.limitedToken, f.configID)
	statusFake, bodyFake := f.get(t, f.limitedToken, f.configID+999999)

	require.Equal(t, http.StatusForbidden, statusReal, "real config, no access: %s", bodyReal)
	require.Equal(t, http.StatusForbidden, statusFake, "nonexistent config: %s", bodyFake)
	require.JSONEq(t, bodyReal, bodyFake, "the two cases must be byte-identical, not just same status")
}

// TestDynamicSecretConfig_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound
// is the narrow exception ADR-096 specifies: a caller who holds
// secrets.read/write GLOBALLY gets a genuine 404 for an ID that truly
// doesn't exist -- distinct from the 403 an unprivileged caller sees for the
// same nonexistent ID.
func TestDynamicSecretConfig_403ForBoth_GloballyPrivilegedCallerGetsRealNotFound(t *testing.T) {
	f := newDynSecret403Fixture(t)

	status, body := f.get(t, f.adminToken, f.configID+999999)
	require.Equal(t, http.StatusNotFound, status, "admin, nonexistent config: %s", body)

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))
}
