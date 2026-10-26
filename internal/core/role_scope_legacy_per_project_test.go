package core

// role_scope_legacy_per_project_test.go — #3546 backport (v0.96), decision of
// ask 3546-phase2-legacy-roles-scope (option a): the legacy single-tier roles
// (admin, editor, viewer, auditor, super_admin) are granted per project today,
// to machine identities and to users (`machine grant-role --project default
// --role viewer`, `rbac assign-role --role admin --project payments`). The
// security fix refuses only the four project_* built-ins without a project; it
// must not refuse any of these.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLegacyRolesGrantedPerProjectStillWork(t *testing.T) {
	c, _ := newBootstrappedCore(t)
	ctx := context.Background()
	admin, err := c.storage.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	def, err := c.storage.GetProjectByName(ctx, "default")
	require.NoError(t, err, "BootstrapSystem seeds the default project")
	payments, err := c.CreateProject(ctx, "payments", "")
	require.NoError(t, err)
	viewer, err := c.storage.GetRoleByName(ctx, "viewer")
	require.NoError(t, err)
	legacyAdmin, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	t.Run("machine identities", func(t *testing.T) {
		mDef, err := c.CreateMachineIdentity(ctx, def.ID, "ci-reader", MachineTypeService, "", "", admin.ID, 0)
		require.NoError(t, err)
		mPay, err := c.CreateMachineIdentity(ctx, payments.ID, "pay-deployer", MachineTypeService, "", "", admin.ID, 0)
		require.NoError(t, err)
		require.NoError(t, c.AssignMachineRole(ctx, mDef.ID, viewer.ID, Scope{ProjectID: def.ID}, admin.ID, false))
		require.NoError(t, c.AssignMachineRole(ctx, mPay.ID, legacyAdmin.ID, Scope{ProjectID: payments.ID}, admin.ID, false))
		got, err := c.storage.GetMachineRoleIDsAt(ctx, mDef.ID, Scope{ProjectID: def.ID})
		require.NoError(t, err)
		require.Equal(t, []uint{viewer.ID}, got)
		got, err = c.storage.GetMachineRoleIDsAt(ctx, mPay.ID, Scope{ProjectID: payments.ID})
		require.NoError(t, err)
		require.Equal(t, []uint{legacyAdmin.ID}, got)
	})

	t.Run("users", func(t *testing.T) {
		u, err := c.CreateUser(ctx, &CreateUserRequest{Username: "pat", Email: "pat@example.com", DisplayName: "Pat", Password: "Correct-Horse-Battery-9"})
		require.NoError(t, err)
		require.NoError(t, c.AssignUserRoleScoped(ctx, "pat@example.com", "viewer", Scope{ProjectID: def.ID}))
		require.NoError(t, c.AssignUserRole(ctx, admin.ID, u.ID, legacyAdmin.ID, Scope{ProjectID: payments.ID}, false))
		grants, err := c.storage.ListAllUserRoleGrants(ctx)
		require.NoError(t, err)
		var mine []string
		for _, g := range grants {
			if g.UserID == u.ID {
				mine = append(mine, fmtGrant("user", g.UserID, g.RoleID, g.ProjectID, g.EnvironmentID))
			}
		}
		require.Contains(t, mine, fmtGrant("user", u.ID, viewer.ID, def.ID, 0))
		require.Contains(t, mine, fmtGrant("user", u.ID, legacyAdmin.ID, payments.ID, 0))
	})

	legacy, err := c.ListGlobalProjectTierRoleGrants(ctx)
	require.NoError(t, err)
	require.Empty(t, legacy, "per-project legacy grants are not reported for review")
}
