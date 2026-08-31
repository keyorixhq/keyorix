// delete_environment_proxy_scope_test.go proves #1648's second finding: the
// /system group's system.write gate alone let ANY holder of that permission
// delete ANY environment on the hub, with no check that the caller is
// authorized against the SPECIFIC environment's project — the same gap
// DeleteProjectProxy's own fix (delete_project_proxy_scope_test.go) closed for
// projects, never propagated to its structurally identical environment
// sibling. The human-facing DELETE /api/v1/environments/{id} route requires
// secrets.delete scoped via ScopeFromEnvParam("id"); DeleteEnvironmentProxy now
// requires the same, layered on top of the group's existing system.write gate.
package http

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// createSystemWriteAndProjectSecretsDeleteTokenForEnv is
// createSystemWriteAndProjectSecretsDeleteToken's environment-route analog:
// system.write GLOBALLY (clears the /system group's own gate) plus
// secrets.delete SCOPED TO projectID only (clears DeleteEnvironmentProxy's new
// per-environment check, since ScopeFromEnvParam resolves the environment's
// OWNING project). A distinct role/username from the project-proxy test's
// helper so the two tests' fixtures never collide within one test binary.
func createSystemWriteAndProjectSecretsDeleteTokenForEnv(t *testing.T, c *core.KeyorixCore, projectID uint) string {
	t.Helper()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sys_write_env_secrets_delete", Email: "sys_write_env_secrets_delete@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "sys_write_env_secrets_delete@example.com", "system_viewer"))

	globalRole, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_delenv_global", Description: "test-only role: system.write only, granted globally",
	})
	require.NoError(t, err)
	scopedRole, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_delenv_scoped", Description: "test-only role: secrets.delete only, granted at one project's scope",
	})
	require.NoError(t, err)

	perms, err := c.ListPermissions(ctx)
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
	require.NotZero(t, systemWriteID, "system.write permission must already be seeded by bootstrap")
	require.NotZero(t, secretsDeleteID, "secrets.delete permission must already be seeded by bootstrap")

	require.NoError(t, c.AssignPermissionToRole(ctx, 0, globalRole.ID, systemWriteID, false))
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, scopedRole.ID, secretsDeleteID, false))
	require.NoError(t, c.Storage().AssignRole(ctx, user.ID, globalRole.ID, coreStorage.Scope{}))
	require.NoError(t, c.Storage().AssignRole(ctx, user.ID, scopedRole.ID, coreStorage.Scope{ProjectID: projectID}))

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "sys_write_env_secrets_delete", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

// TestDeleteEnvironmentProxy_SystemWriteOnly_CannotDeleteEnvironment is the
// fix's red case: a caller holding system.write but NOT secrets.delete on the
// target environment's project must be refused — before the fix, the group's
// system.write gate was the ONLY check, so this caller could delete any
// environment on the hub. The scope predicate is asserted by querying storage
// directly afterward (the environment must still exist), not just by reading
// the handler's response.
func TestDeleteEnvironmentProxy_SystemWriteOnly_CannotDeleteEnvironment(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstream := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, upstream) // bootstrap admin + seed roles/permissions (incl. system.write, secrets.delete)
	project, err := upstream.CreateProject(ctx, "Delete Env Scope Test Project", "")
	require.NoError(t, err)
	env, err := upstream.CreateEnvironment(ctx, project.ID, "scope-test-env")
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteOnlyToken(t, upstream)
	rs := newDeleteProjectScopeRemoteClient(t, srv.URL, token)

	err = rs.DeleteEnvironment(ctx, env.ID)
	require.Error(t, err, "CEILING VIOLATED: system.write alone must not be sufficient to delete an environment in a project the caller holds no secrets.delete grant on")

	// Scope predicate asserted at the query, not just the handler response.
	_, getErr := upstream.Storage().GetEnvironment(ctx, env.ID)
	assert.NoError(t, getErr, "the environment must still exist after a denied delete attempt")
}

// TestDeleteEnvironmentProxy_SystemWriteAndScopedSecretsDelete_Succeeds is the
// fix's positive control: the legitimate caller the fix must keep working --
// system.write (to clear the group's own gate) plus secrets.delete scoped to
// the environment's project (to clear the new per-environment check) -- can
// still delete it, exactly like the human-facing DeleteEnvironment route
// already allows.
func TestDeleteEnvironmentProxy_SystemWriteAndScopedSecretsDelete_Succeeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstream := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, upstream)
	project, err := upstream.CreateProject(ctx, "Delete Env Scope Allow Test Project", "")
	require.NoError(t, err)
	env, err := upstream.CreateEnvironment(ctx, project.ID, "scope-allow-test-env")
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteAndProjectSecretsDeleteTokenForEnv(t, upstream, project.ID)
	rs := newDeleteProjectScopeRemoteClient(t, srv.URL, token)

	require.NoError(t, rs.DeleteEnvironment(ctx, env.ID))

	// Scope predicate asserted at the query, not just the handler response.
	_, getErr := upstream.Storage().GetEnvironment(ctx, env.ID)
	assert.Error(t, getErr, "the environment must actually be gone after an authorized delete")
}
