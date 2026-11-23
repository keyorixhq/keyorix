package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestSuspendProjectSecrets_ProjectGate is #4161 known-04 row 25 (bulk.suspend):
// core decides the route gate of POST /projects/{id}/secrets/suspend-all,
// secrets.write at the project, before any secret is read or written. A project
// viewer holding a per-secret ACL write passes the per-secret re-check on that
// secret but not the project gate, so the whole request is refused: nothing is
// suspended, nothing is marked, no audit row is written. A project developer and
// the bootstrap admin, who hold secrets.write@project, still suspend.
func TestSuspendProjectSecrets_ProjectGate(t *testing.T) {
	t.Parallel()
	for _, clear := range []bool{false, true} {
		name := "plain"
		if clear {
			name = "clear_synced_copies"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			opts := SuspendOptions{ClearSyncedCopies: clear}

			proj, err := st.CreateProject(ctx, &models.Project{Name: "bulk-suspend-gate-" + name})
			require.NoError(t, err)
			env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
			require.NoError(t, err)
			assign := func(login, roleName string) *models.User {
				u, err := st.CreateUser(ctx, foldedTestUser(t, login, login+"@example.com"))
				require.NoError(t, err)
				role, err := st.GetRoleByName(ctx, roleName)
				require.NoError(t, err)
				require.NoError(t, st.AssignRole(ctx, u.ID, role.ID, storage.Scope{ProjectID: proj.ID}))
				return u
			}
			developer := assign("bulk-gate-dev-"+name, "project_developer")
			viewer := assign("bulk-gate-viewer-"+name, "project_viewer")

			mk := func(secretName string) *models.SecretNode {
				s, err := st.CreateSecret(ctx, &models.SecretNode{
					Name: secretName, ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
					IsSecret: true, OwnerID: developer.ID, Status: SecretStatusActive,
				})
				require.NoError(t, err)
				return s
			}
			aclGranted := mk("acl-granted")
			other := mk("other")
			require.NoError(t, st.CreateOrUpdateSecretACL(ctx, &models.SecretACL{
				SecretID: aclGranted.ID, UserID: viewer.ID, Permissions: `["secrets.read","secrets.write"]`, GrantedBy: developer.ID,
			}))

			// Precondition: the per-secret re-check alone lets the viewer suspend the
			// ACL-granted secret, so a refusal below is the project gate, not that check.
			require.NoError(t, c.enforceSecretWriteGate(ctx, aclGranted.ID, viewer.ID, SecretActionSuspend, SecretActionSuspend),
				"precondition: the per-secret ACL write passes the per-secret re-check")

			auditRows := func(eventType string) int64 {
				var n int64
				require.NoError(t, st.DB().Model(&models.AuditEvent{}).Where("event_type = ?", eventType).Count(&n).Error)
				return n
			}
			stored := func(id uint) *models.SecretNode {
				s, err := st.GetSecret(ctx, id)
				require.NoError(t, err)
				return s
			}

			n, err := c.SuspendProjectSecretsWithOptions(ctx, proj.ID, viewer.ID, "acl writer", opts)
			require.ErrorIs(t, err, ErrPermissionDenied, "a per-secret ACL write is not secrets.write@project")
			require.Zero(t, n)
			for _, s := range []*models.SecretNode{aclGranted, other} {
				got := stored(s.ID)
				require.Equal(t, SecretStatusActive, got.Status, "%s: nothing is suspended", s.Name)
				require.False(t, got.SuspendClearSyncedCopies, "%s: nothing is marked", s.Name)
			}
			require.Zero(t, auditRows("secret.bulk_suspend_attempted"), "a refused request writes no bulk row")
			require.Zero(t, auditRows(EventSecretSuspended), "and no per-secret row")

			// Positive controls: secrets.write@project through a project role, and
			// through the bootstrap admin's global role.
			n, err = c.SuspendProjectSecretsWithOptions(ctx, proj.ID, developer.ID, "developer", opts)
			require.NoError(t, err)
			require.Equal(t, 2, n, "the developer suspends both secrets")
			for _, s := range []*models.SecretNode{aclGranted, other} {
				require.Equal(t, SecretStatusSuspended, stored(s.ID).Status, s.Name)
			}

			admin, err := st.GetUserByUsername(ctx, "admin")
			require.NoError(t, err)
			_, err = c.ResumeProjectSecrets(ctx, proj.ID, admin.ID)
			require.NoError(t, err)
			n, err = c.SuspendProjectSecretsWithOptions(ctx, proj.ID, admin.ID, "admin", opts)
			require.NoError(t, err)
			require.Equal(t, 2, n, "the admin suspends both secrets")
		})
	}
}
