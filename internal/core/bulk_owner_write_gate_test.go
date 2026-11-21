package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestOwnerWithoutSecretsWrite_BulkOpsSkipTheirSecrets is CORE-AUTHZ-RACE-NOV-1
// item 2, the project-scope sibling of #4508: BulkRenameSecrets,
// SuspendProjectSecretsWithOptions, ResumeProjectSecrets and ExtendExpiringSecrets
// re-checked each secret with EnforceSecretWritePermission, which the owner pass
// alone satisfies, while REST gates all four on project-scope secrets.write with no
// owner pass. A project viewer who owns every secret in the project could rename,
// suspend, resume or extend them all through a direct core call; now each bulk op
// skips a secret its OWNER cannot write by the route's gate (enforceSecretWriteGate),
// so the viewer-owner changes nothing. The project-developer owner is the positive
// control: the same calls act on every secret.
func TestOwnerWithoutSecretsWrite_BulkOpsSkipTheirSecrets(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		role    string
		allowed bool
	}{
		{"project_viewer", false},
		{"project_developer", true},
	} {
		t.Run(tc.role, func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()

			proj, err := st.CreateProject(ctx, &models.Project{Name: "bulk-owner-gate-" + tc.role})
			require.NoError(t, err)
			owner, err := st.CreateUser(ctx, foldedTestUser(t, "bulk-owner-"+tc.role, "bulk-owner-"+tc.role+"@example.com"))
			require.NoError(t, err)
			role, err := st.GetRoleByName(ctx, tc.role)
			require.NoError(t, err)
			require.NoError(t, st.AssignRole(ctx, owner.ID, role.ID, storage.Scope{ProjectID: proj.ID}))
			env, err := st.CreateEnvironment(ctx, &models.Environment{Name: "production", ProjectID: proj.ID})
			require.NoError(t, err) // the bulk ops list the project's secrets through their environment

			mk := func(name, status string, exp *time.Time) *models.SecretNode {
				s, err := st.CreateSecret(ctx, &models.SecretNode{
					Name: name, ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
					IsSecret: true, OwnerID: owner.ID, Status: status, Expiration: exp,
				})
				require.NoError(t, err)
				return s
			}
			soon := c.now().Add(24 * time.Hour).UTC()
			active := mk("owned-active", SecretStatusActive, nil)
			suspended := mk("owned-suspended", SecretStatusSuspended, nil)
			expiring := mk("owned-expiring", SecretStatusActive, &soon)

			report, err := c.BulkRenameSecrets(ctx, proj.ID, []SecretRename{{ID: active.ID, NewName: "owned-renamed"}}, false, "owner", owner.ID, "", "")
			require.NoError(t, err)
			suspendedN, err := c.SuspendProjectSecrets(ctx, proj.ID, owner.ID, "owner gate")
			require.NoError(t, err)
			resumedN, err := c.ResumeProjectSecrets(ctx, proj.ID, owner.ID)
			require.NoError(t, err)
			extendedN, _, err := c.ExtendExpiringSecrets(ctx, proj.ID, 7, 30, "owner", owner.ID)
			require.NoError(t, err)

			after := func(id uint) *models.SecretNode {
				s, err := st.GetSecret(ctx, id)
				require.NoError(t, err)
				return s
			}
			if tc.allowed {
				require.Equal(t, 1, report.Renamed, "rename: %+v", report)
				require.Equal(t, "owned-renamed", after(active.ID).Name)
				// The bulk suspend ran before the resume: it suspended the two active
				// secrets, and the resume then brought all three back.
				require.Equal(t, 2, suspendedN, "suspend")
				require.Equal(t, 3, resumedN, "resume")
				require.Equal(t, 1, extendedN, "extend")
				require.True(t, after(expiring.ID).Expiration.After(soon), "the expiry moved out")
				return
			}
			require.Equal(t, 0, report.Renamed, "rename: %+v", report)
			require.Equal(t, 1, report.Skipped, "rename: %+v", report)
			require.Equal(t, "owned-active", after(active.ID).Name, "the name is unchanged")
			require.Equal(t, 0, suspendedN, "suspend")
			require.Equal(t, SecretStatusActive, after(active.ID).Status, "the active secret stays active")
			require.Equal(t, 0, resumedN, "resume")
			require.Equal(t, SecretStatusSuspended, after(suspended.ID).Status, "the suspended secret stays suspended")
			require.Equal(t, 0, extendedN, "extend")
			require.True(t, after(expiring.ID).Expiration.Equal(soon), "the expiry is unchanged")
		})
	}
}
