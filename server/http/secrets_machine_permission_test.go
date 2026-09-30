// secrets_machine_permission_test.go — W1 (Session S benchmark Bug 2): a machine
// identity holding secrets.write could create and read a secret but could not
// update, rotate, roll back, or list versions of one — every one of those
// entry points called a core *WithPermissionCheck function that hard-fails
// with "user ID is required for permission checking" whenever userID is 0,
// which is how every machine caller's UserID reads by construction (ADR-030).
// The route's RequireScopedSecretPermission gate had already authorized the
// machine principal via AuthorizeSecretPrincipal before the handler ever
// reached that dead-end check.
//
// This file drives the real HTTP router with a real, issued machine bearer
// token (not a hand-built UserContext) end-to-end through the full stack:
// auth middleware -> route-scoped permission gate -> handler -> core.
package http

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/server/http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSecretsMachineTestServer spins up a full HTTP router backed by the given core.
func newSecretsMachineTestServer(t *testing.T, c *core.KeyorixCore) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "8080"},
		},
	}
	router, err := NewRouter(cfg, c)
	require.NoError(t, err)
	return httptest.NewServer(router)
}

// doMachineRequest issues an authenticated request against srv with a machine
// bearer token and returns the status code and raw body (read once, so
// callers don't need their own io.ReadAll/Close boilerplate).
func doMachineRequest(t *testing.T, srv *httptest.Server, token, method, path string, body []byte) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, reader)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	// Each request fires its audit write from a detached goroutine (handlers.goSafe
	// and core.goSafe). The test DB is a shared-cache in-memory SQLite, where a
	// write that overlaps the previous request's still-running audit write fails
	// with SQLITE_LOCKED_SHAREDCACHE ("database table is locked (262)") -- which
	// _busy_timeout never retries -- surfacing as a 500 on rotate/rollback. Drain
	// both before returning so sequential requests in these tests really are
	// sequential. Production (file DB, no shared cache) gets SQLITE_BUSY instead,
	// which busy_timeout does retry.
	handlers.DrainBackgroundGoroutines()
	core.DrainBackgroundGoroutines()
	return resp.StatusCode, string(raw)
}

// machineSecretFixture bootstraps a full-schema test core + router, an admin,
// a project/environment, one secret in it, and a machine identity issued a
// real bearer token and granted roleName at the secret's project scope (or at
// grantProjectID's scope, when it differs — the cross-project-scope test
// needs the grant and the secret in DIFFERENT projects). Returns the server,
// the raw machine token, and the secret's ID.
func machineSecretFixture(t *testing.T, roleName string, grantProjectID uint) (*httptest.Server, string, uint) {
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
	secretProject := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "w1-machine-mutation-target", Value: []byte("v1-initial"),
		ProjectID: secretProject.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	// grantProjectID == 0 means "grant at the secret's own project" (the
	// authorized-machine case); a nonzero, DIFFERENT value is how the
	// cross-project-scope test proves the grant doesn't leak.
	if grantProjectID == 0 {
		grantProjectID = secretProject.ID
	}

	mi, err := c.CreateMachineIdentity(ctx, grantProjectID, "w1-ci-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, grantProjectID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "w1-ci-token"})
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	var roleID uint
	for _, r := range roles {
		if r.Name == roleName {
			roleID = r.ID
			break
		}
	}
	require.NotZero(t, roleID, "builtin role %q must exist", roleName)
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID, core.Scope{ProjectID: grantProjectID}, admin.ID, false))

	srv := newSecretsMachineTestServer(t, c)
	return srv, tok.PlainToken, secret.ID
}

// TestSecretMutations_MachineWithWriteRole_NotBlockedByUserIDGuard sweeps every
// secrets/versions mutation/read entry point that used to hard-fail a machine
// caller with "user ID is required for permission checking" (W1): update,
// rotate, rollback, and list-versions. A machine holding project_developer
// (secrets.read + secrets.write + secrets.delete, see auth_bootstrap.go) must
// reach every one of them without that error, exactly like a human with the
// same effective permission already could.
func TestSecretMutations_MachineWithWriteRole_NotBlockedByUserIDGuard(t *testing.T) {
	srv, token, secretID := machineSecretFixture(t, "project_developer", 0)
	defer srv.Close()
	path := "/api/v1/secrets/" + strconv.FormatUint(uint64(secretID), 10)

	const userIDGuardMsg = "user ID is required"

	// PUT — update (the confirmed Bug 2 repro).
	updateBody, err := json.Marshal(map[string]any{"value": "v2-updated"})
	require.NoError(t, err)
	status, body := doMachineRequest(t, srv, token, http.MethodPut, path, updateBody)
	assert.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to update: %s", body)
	assert.NotContains(t, body, userIDGuardMsg)

	// GET — list versions.
	status, body = doMachineRequest(t, srv, token, http.MethodGet, path+"/versions", nil)
	assert.Equal(t, http.StatusOK, status, "machine with secrets.read must be able to list versions: %s", body)
	assert.NotContains(t, body, userIDGuardMsg)

	// POST — rotate.
	rotateBody, err := json.Marshal(map[string]any{"new_value": "v3-rotated-value"})
	require.NoError(t, err)
	status, body = doMachineRequest(t, srv, token, http.MethodPost, path+"/rotate", rotateBody)
	assert.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to rotate: %s", body)
	assert.NotContains(t, body, userIDGuardMsg)

	// POST — rollback to version 1 (the original, pre-rotation value).
	rollbackBody, err := json.Marshal(map[string]any{"version": 1})
	require.NoError(t, err)
	status, body = doMachineRequest(t, srv, token, http.MethodPost, path+"/rollback", rollbackBody)
	assert.Equal(t, http.StatusOK, status, "machine with secrets.write must be able to roll back: %s", body)
	assert.NotContains(t, body, userIDGuardMsg)

	// DELETE — already fixed before this campaign (#1808), kept in the sweep
	// so the whole mutation family is proven together, not piecemeal.
	status, body = doMachineRequest(t, srv, token, http.MethodDelete, path, nil)
	assert.Equal(t, http.StatusNoContent, status, "machine with secrets.delete must be able to delete: %s", body)
	assert.NotContains(t, body, userIDGuardMsg)
}

// TestUpdateSecret_MachineWithoutWritePermission_Forbidden proves the fix does
// not open the route for a machine holding read-only access: project_viewer
// carries secrets.read but not secrets.write.
func TestUpdateSecret_MachineWithoutWritePermission_Forbidden(t *testing.T) {
	srv, token, secretID := machineSecretFixture(t, "project_viewer", 0)
	defer srv.Close()
	path := "/api/v1/secrets/" + strconv.FormatUint(uint64(secretID), 10)

	body, err := json.Marshal(map[string]any{"value": "should-not-apply"})
	require.NoError(t, err)
	status, respBody := doMachineRequest(t, srv, token, http.MethodPut, path, body)
	assert.Equal(t, http.StatusForbidden, status, "machine without secrets.write must be denied, not 400: %s", respBody)
}

// TestUpdateSecret_MachineScopedToOtherProject_Forbidden proves a machine
// granted project_developer at project A cannot write a secret that lives in
// project B — the route-level scope check, not just the permission name,
// must still gate the machine principal.
func TestUpdateSecret_MachineScopedToOtherProject_Forbidden(t *testing.T) {
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
	secretProject := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "w1-cross-project-target", Value: []byte("v1-initial"),
		ProjectID: secretProject.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	otherProject, err := c.CreateProject(ctx, "w1-other-project", "")
	require.NoError(t, err)

	mi, err := c.CreateMachineIdentity(ctx, otherProject.ID, "w1-scoped-runner", "ci", "", "", admin.ID, 0)
	require.NoError(t, err)
	tok, err := c.IssueMachineToken(ctx, otherProject.ID, mi.ID, admin.ID, core.IssueMachineTokenParams{Name: "w1-scoped-token"})
	require.NoError(t, err)

	roles, err := c.Storage().ListRoles(ctx)
	require.NoError(t, err)
	var roleID uint
	for _, r := range roles {
		if r.Name == "project_developer" {
			roleID = r.ID
			break
		}
	}
	require.NotZero(t, roleID)
	require.NoError(t, c.AssignMachineRole(ctx, mi.ID, roleID, core.Scope{ProjectID: otherProject.ID}, admin.ID, false))

	srv := newSecretsMachineTestServer(t, c)
	defer srv.Close()

	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	body, err := json.Marshal(map[string]any{"value": "should-not-apply"})
	require.NoError(t, err)
	status, respBody := doMachineRequest(t, srv, tok.PlainToken, http.MethodPut, path, body)
	assert.Equal(t, http.StatusForbidden, status,
		"a machine's project_developer grant at a DIFFERENT project must not authorize this secret: %s", respBody)
}

// TestUpdateSecret_HumanPath_Unchanged is the counterpart proving the isMachine
// split did not disturb the existing per-user owner/sharing enforcement: a
// human with no role at all must still be denied.
func TestUpdateSecret_HumanPath_Unchanged(t *testing.T) {
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
	project := projects[0]
	envs, err := c.ListEnvironments(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, envs)
	env := envs[0]

	secret, err := c.CreateSecret(ctx, &core.CreateSecretRequest{
		Name: "w1-human-path-target", Value: []byte("v1-initial"),
		ProjectID: project.ID, EnvironmentID: env.ID, Type: "generic",
		CreatedBy: admin.Username, OwnerID: admin.ID,
	})
	require.NoError(t, err)

	_, err = c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "w1_noperm", Email: "w1_noperm@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "w1_noperm@example.com", "system_viewer"))
	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "w1_noperm", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)

	srv := newSecretsMachineTestServer(t, c)
	defer srv.Close()

	path := fmt.Sprintf("/api/v1/secrets/%d", secret.ID)
	body, err := json.Marshal(map[string]any{"value": "should-not-apply"})
	require.NoError(t, err)
	status, respBody := doMachineRequest(t, srv, sess.SessionToken, http.MethodPut, path, body)
	assert.Equal(t, http.StatusForbidden, status, "a human with no relevant role must still be denied: %s", respBody)
	assert.False(t, strings.Contains(respBody, "user ID is required"))
}
