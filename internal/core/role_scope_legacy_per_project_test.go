package core

// role_scope_legacy_per_project_test.go — #3546 Phase 2, decision of ask
// 3546-phase2-legacy-roles-scope (option a): the legacy single-tier roles
// (admin, editor, viewer, auditor, super_admin) are assignable "any", NOT
// "global", because installs grant them per project today, to machine
// identities and to users (`machine grant-role --project default --role
// viewer`, `rbac assign-role --role admin --project payments`). A security fix
// must not refuse what works; tightening them to global is a separate,
// deliberate change with its own UPGRADING note.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestLegacyRolesAreAssignableAnywhere pins the decision itself, by literal,
// so flipping the seed table (one line) fails here and not only in callers.
func TestLegacyRolesAreAssignableAnywhere(t *testing.T) {
	for _, name := range []string{"admin", "editor", "viewer", "auditor", "super_admin"} {
		require.Equal(t, models.RoleAssignableAny, models.BuiltinRoleAssignableScopes[name],
			"legacy role %s must stay assignable at a project and globally (ask 3546-phase2-legacy-roles-scope)", name)
	}
}

// TestLegacyRolesGrantedPerProjectStillWork drives the per-project grants of
// legacy roles that worked before #3546, to machine identities and to users,
// and reads the grant rows back (the effect, not only a nil error).
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
		// machine grant-role ci-reader --project default --role viewer
		require.NoError(t, c.AssignMachineRole(ctx, mDef.ID, viewer.ID, Scope{ProjectID: def.ID}, admin.ID, false))
		// machine grant-role pay-deployer --project payments --role admin
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
		// rbac assign-role --user pat@example.com --role viewer --project default (local CLI path)
		require.NoError(t, c.AssignUserRoleScoped(ctx, "pat@example.com", "viewer", Scope{ProjectID: def.ID}))
		// POST /api/v1/user-roles {role: admin, project_id: payments}
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

	// Nothing above is outside its role's scope, so the startup review lists none.
	outside, err := c.ListRoleGrantsOutsideAssignableScope(ctx)
	require.NoError(t, err)
	require.Empty(t, outside)
}
