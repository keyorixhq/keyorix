// delete_project_proxy_scope_test.go proves the G80 documented-exception
// re-verification sweep's DeleteProjectProxy finding (2026-08-25): the /system
// group's system.write gate alone let ANY holder of that permission delete ANY
// project on the hub, with no check that the caller is actually authorized
// against the SPECIFIC project targeted — including a caller whose system.write
// grant exists for a narrow, unrelated purpose (audit checkpoints, admin job
// triggers; see server/http/router.go's own doc comment on the /system group).
// The human-facing DELETE /api/v1/projects/{id} route requires secrets.delete
// scoped to that project (RequireScopedPermission(permSecretsDelete,
// projectScope)); DeleteProjectProxy now requires the same, layered on top of
// the group's existing system.write gate, via the same actor-kind-aware
// middleware.
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
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// createSystemWriteAndProjectSecretsDeleteToken creates a human user holding
// system.write GLOBALLY (so it clears the /system group's own gate) and
// secrets.delete SCOPED TO projectID only (so it clears DeleteProjectProxy's
// new per-project check for that project, and only that project) — via a
// custom role well outside adminRoleNames, same rationale as
// createSystemWriteOnlyToken. Represents the legitimate caller the fix is meant
// to keep working: someone who actually holds the same authority the
// human-facing DeleteProject route already requires for this specific project.
func createSystemWriteAndProjectSecretsDeleteToken(t *testing.T, c *core.KeyorixCore, projectID uint) string {
	t.Helper()
	ctx := context.Background()

	user, err := c.CreateUser(ctx, &core.CreateUserRequest{
		Username: "sys_write_proj_secrets_delete", Email: "sys_write_proj_secrets_delete@example.com", Password: "Qr7#Kp2$Lm5@Vn9!",
	})
	require.NoError(t, err)
	require.NoError(t, c.RemoveRoleFromUser(ctx, "sys_write_proj_secrets_delete@example.com", "system_viewer"))

	globalRole, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_delproj_global", Description: "test-only role: system.write only, granted globally",
	})
	require.NoError(t, err)
	scopedRole, err := c.Storage().CreateRole(ctx, &models.Role{
		Name: "ceiling_test_system_writer_delproj_scoped", Description: "test-only role: secrets.delete only, granted at one project's scope",
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

	sess, _, err := c.Login(ctx, &core.LoginRequest{Username: "sys_write_proj_secrets_delete", Password: "Qr7#Kp2$Lm5@Vn9!"})
	require.NoError(t, err)
	return sess.SessionToken
}

// newDeleteProjectScopeRemoteClient builds a fresh *store.RemoteStorage backed
// by the given token, isolated per-caller exactly like
// newBreakGlassRemoteClient — see that helper's comment for why a shared client
// across differently-privileged callers in the same test would be wrong.
func newDeleteProjectScopeRemoteClient(t *testing.T, baseURL, apiKey string) *store.RemoteStorage {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        baseURL,
		APIKey:         apiKey,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	return rs
}

// TestDeleteProjectProxy_SystemWriteOnly_CannotDeleteProject is the fix's red
// case: a caller holding system.write but NOT secrets.delete on the target
// project must be refused — before the fix, the group's system.write gate was
// the ONLY check, so this caller could delete any project on the hub.
func TestDeleteProjectProxy_SystemWriteOnly_CannotDeleteProject(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstream := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, upstream) // bootstrap admin + seed roles/permissions (incl. system.write, secrets.delete)
	project, err := upstream.CreateProject(ctx, "Delete Scope Test Project", "")
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteOnlyToken(t, upstream)
	rs := newDeleteProjectScopeRemoteClient(t, srv.URL, token)

	err = rs.DeleteProject(ctx, project.ID)
	require.Error(t, err, "CEILING VIOLATED: system.write alone must not be sufficient to delete a project the caller holds no secrets.delete grant on")

	_, getErr := upstream.Storage().GetProject(ctx, project.ID)
	assert.NoError(t, getErr, "the project must still exist after a denied delete attempt")
}

// TestDeleteProjectProxy_SystemWriteAndScopedSecretsDelete_Succeeds is the
// fix's control: the legitimate caller the fix must keep working — system.write
// (to clear the group's own gate) plus secrets.delete scoped to THIS project
// (to clear the new per-project check) — can still delete it, exactly like the
// human-facing DeleteProject route already allows.
func TestDeleteProjectProxy_SystemWriteAndScopedSecretsDelete_Succeeds(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting())
	defer i18n.ResetForTesting()

	upstream := newTestCore(t)
	ctx := context.Background()
	createTestToken(t, upstream) // bootstrap admin + seed roles/permissions (incl. system.write, secrets.delete)
	project, err := upstream.CreateProject(ctx, "Delete Scope Allow Test Project", "")
	require.NoError(t, err)

	cfg := &config.Config{}
	router, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	srv := httptest.NewServer(router)
	defer srv.Close()

	token := createSystemWriteAndProjectSecretsDeleteToken(t, upstream, project.ID)
	rs := newDeleteProjectScopeRemoteClient(t, srv.URL, token)

	require.NoError(t, rs.DeleteProject(ctx, project.ID))

	_, getErr := upstream.Storage().GetProject(ctx, project.ID)
	assert.Error(t, getErr, "the project must actually be gone after an authorized delete")
}
