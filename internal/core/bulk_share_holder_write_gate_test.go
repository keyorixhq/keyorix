package core

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestWriteShareHolderWithoutSecretsWrite_BulkOpsSkip is the share-holder side of
// CORE-AUTHZ-RACE-NOV-1 item 2 (#4559 review, MEDIUM-1). The bulk routes gate on
// project-scope secrets.write with no share term, so a project viewer who holds a
// WRITE share on a secret someone else owns must not rename, suspend, resume or
// extend it through a direct core call either. The rename re-check used a
// share-elevating check action (SecretActionUpdateMetadata), so the share alone
// granted the rename; it now uses the non-elevating "" like MoveSecret. Suspend,
// resume and extend were never elevated; their cases lock that in.
func TestWriteShareHolderWithoutSecretsWrite_BulkOpsSkip(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	proj, err := st.CreateProject(ctx, &models.Project{Name: "bulk-share-holder-gate"})
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
	owner := assign("bulk-share-owner", "project_developer")
	holder := assign("bulk-share-holder", "project_viewer")

	mk := func(name, status string, exp *time.Time) *models.SecretNode {
		s, err := st.CreateSecret(ctx, &models.SecretNode{
			Name: name, ProjectID: proj.ID, EnvironmentID: env.ID, Type: "password",
			IsSecret: true, OwnerID: owner.ID, Status: status, Expiration: exp,
		})
		require.NoError(t, err)
		_, err = st.CreateShareRecord(ctx, &models.ShareRecord{
			SecretID: s.ID, OwnerID: owner.ID, RecipientID: holder.ID, Permission: "write", CreatedAt: time.Now(),
		})
		require.NoError(t, err)
		return s
	}
	soon := c.now().Add(24 * time.Hour).UTC()
	active := mk("shared-active", SecretStatusActive, nil)
	suspended := mk("shared-suspended", SecretStatusSuspended, nil)
	expiring := mk("shared-expiring", SecretStatusActive, &soon)

	report, err := c.BulkRenameSecrets(ctx, proj.ID, []SecretRename{{ID: active.ID, NewName: "shared-renamed"}}, false, "holder", holder.ID, "", "")
	require.NoError(t, err)
	suspendedN, err := c.SuspendProjectSecrets(ctx, proj.ID, holder.ID, "share holder gate")
	require.NoError(t, err)
	resumedN, err := c.ResumeProjectSecrets(ctx, proj.ID, holder.ID)
	require.NoError(t, err)
	extendedN, _, err := c.ExtendExpiringSecrets(ctx, proj.ID, 7, 30, "holder", holder.ID)
	require.NoError(t, err)

	after := func(id uint) *models.SecretNode {
		s, err := st.GetSecret(ctx, id)
		require.NoError(t, err)
		return s
	}
	require.Equal(t, 0, report.Renamed, "rename: %+v", report)
	require.Equal(t, 1, report.Skipped, "rename: %+v", report)
	require.Equal(t, "secret not found", report.Outcomes[0].Reason, "the skip keeps the uniform #G14 reason")
	require.Equal(t, "shared-active", after(active.ID).Name, "the name is unchanged")
	require.Equal(t, 0, suspendedN, "suspend")
	require.Equal(t, SecretStatusActive, after(active.ID).Status, "the active secret stays active")
	require.Equal(t, 0, resumedN, "resume")
	require.Equal(t, SecretStatusSuspended, after(suspended.ID).Status, "the suspended secret stays suspended")
	require.Equal(t, 0, extendedN, "extend")
	require.True(t, after(expiring.ID).Expiration.Equal(soon), "the expiry is unchanged")

	// Positive control: the owner (project_developer) still renames the same secret,
	// so the skip above is the share term, not a broken fixture.
	report, err = c.BulkRenameSecrets(ctx, proj.ID, []SecretRename{{ID: active.ID, NewName: "shared-renamed"}}, false, "owner", owner.ID, "", "")
	require.NoError(t, err)
	require.Equal(t, 1, report.Renamed, "owner rename: %+v", report)
}
