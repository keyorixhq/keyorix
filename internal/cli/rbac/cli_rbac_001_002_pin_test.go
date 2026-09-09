// cli_rbac_001_002_pin_test.go — permanent regression pins for cli-rbac-001 and
// cli-rbac-002.
//
// Both findings had the same shape: group_role.go's embedded-mode
// runAssignRoleToGroup/runRemoveRoleFromGroup called raw storage methods
// (st.AssignRoleToGroup / st.RemoveRoleFromGroup) directly instead of going
// through core.KeyorixCore, silently skipping the security checks
// core.KeyorixCore.AssignRoleToGroup/RemoveRoleFromGroup enforce:
//
//   - cli-rbac-001: requireGroupGrantNoSoDViolation (separation-of-duties) —
//     granting a group a role that, combined with a member's other permissions,
//     would newly complete an SoD policy must be refused.
//   - cli-rbac-002: guardLastGlobalAdminGroupRole (last-global-admin lockout) —
//     removing a group's role grant that is the install's LAST global
//     super_admin/admin/system_admin-conferring grant must be refused.
//
// Both were fixed in commit 76dbc529 (PR #1395): group_role.go now routes
// through core.NewKeyorixCore(st).AssignRoleToGroup(...) /
// .RemoveRoleFromGroup(...). These tests call the REAL CLI entrypoints
// (runAssignRoleToGroup / runRemoveRoleFromGroup) against a real,
// file-backed SQLite database built via common.InitializeStorage() — the
// exact embedded-mode code path a real `keyorix rbac assign-role-to-group` /
// `remove-role-from-group` invocation takes — so a future regression that
// reintroduces the raw-storage-call bypass is caught by CI, not just by a
// one-off manual verification pass.
package rbac

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/cli/common"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustFoldedName is a small test-local helper: every seeded role/group name
// below is already pure-lowercase ASCII, so folding can never fail — any
// error here would indicate a broken test fixture, not a real name
// containing anything a FoldedName should reject.
func mustFoldedName(t *testing.T, raw string) identity.FoldedName {
	t.Helper()
	n, err := identity.NewFoldedName(raw)
	require.NoError(t, err)
	return n
}

// ── cli-rbac-001: SoD enforcement on the embedded group-role-assignment path ──

// TestCliRbac001_AssignRoleToGroup_EnforcesSoD proves that the embedded-mode
// `assign-role-to-group` CLI command still enforces separation-of-duties after
// #1395's fix routes it through core.KeyorixCore.AssignRoleToGroup instead of
// calling st.AssignRoleToGroup directly. Before the fix, this exact scenario
// (a group member who already holds one side of a toxic-permission pair
// directly, and a group-role grant that would hand them the other side)
// succeeded silently — the raw storage call has no idea an SoD policy exists.
func TestCliRbac001_AssignRoleToGroup_EnforcesSoD(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting()) // GetRoleByName's error path formats via i18n.T; guarded by sync.Once, safe across tests
	setupEmbeddedMode(t)
	t.Setenv("KEYORIX_CLI_ACTOR", "") // actorID resolves to 0 (system pseudo-actor): exercises the SoD gate only, not the unrelated escalation-by-proxy ceiling check

	st, err := common.InitializeStorage()
	require.NoError(t, err)
	ctx := context.Background()

	// Role A carries perm.a; role B carries perm.b. Neither is admin-tier, so
	// the SoD gate's admin-bypass never short-circuits this test.
	roleA, err := st.CreateRole(ctx, mustFoldedName(t, "role-a-sod"), "holds perm.a")
	require.NoError(t, err)
	roleB, err := st.CreateRole(ctx, mustFoldedName(t, "role-b-sod"), "holds perm.b")
	require.NoError(t, err)

	permA, err := st.CreatePermission(ctx, &models.Permission{Name: "perm.a.sod", Description: "side A", Resource: "sod", Action: "a"})
	require.NoError(t, err)
	permB, err := st.CreatePermission(ctx, &models.Permission{Name: "perm.b.sod", Description: "side B", Resource: "sod", Action: "b"})
	require.NoError(t, err)
	require.NoError(t, st.AssignPermissionToRole(ctx, roleA.ID, permA.ID))
	require.NoError(t, st.AssignPermissionToRole(ctx, roleB.ID, permB.ID))

	// A user who directly holds role A (perm.a) ...
	user, err := st.CreateUser(ctx, &models.User{
		Username:       "sod-member",
		UsernameFolded: "sod-member",
		Email:          "sod-member@test.com",
		EmailFolded:    "sod-member@test.com",
	})
	require.NoError(t, err)
	require.NoError(t, st.AssignRole(ctx, user.ID, roleA.ID, storage.Scope{}))

	// ... and is a member of the group this test will try to grant role B to.
	group, err := st.CreateGroup(ctx, &models.Group{Name: "sod-test-group", NameFolded: "sod-test-group"})
	require.NoError(t, err)
	require.NoError(t, st.AddUserToGroup(ctx, user.ID, group.ID, 0))

	// A policy declaring perm.a + perm.b a toxic combination.
	_, err = st.CreateSoDPolicy(ctx, &models.SoDPolicy{
		Name:        "sod-a-vs-b",
		PermissionA: permA.Name,
		PermissionB: permB.Name,
	})
	require.NoError(t, err)

	// Point the real CLI entrypoint at group=sod-test-group, role=role-b-sod —
	// granting it to the group would newly complete the policy for the member
	// seeded above.
	origGroup, origRole, origProj, origEnv, origTTL := groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL
	t.Cleanup(func() {
		groupRoleGroupFlag, groupRoleName, groupRoleProjectFlag, groupRoleEnvFlag, groupRoleTTL = origGroup, origRole, origProj, origEnv, origTTL
	})
	groupRoleGroupFlag = "sod-test-group"
	groupRoleName = "role-b-sod"
	groupRoleProjectFlag = ""
	groupRoleEnvFlag = ""
	groupRoleTTL = 0

	runErr := runAssignRoleToGroup(nil, nil)
	require.Error(t, runErr, "granting role-b-sod to the group must be blocked: it would create a separation-of-duties violation for its member")
	assert.Contains(t, runErr.Error(), "separation-of-duties")

	// The blocked grant must not have been persisted.
	grants, err := st.GetGroupRoleGrants(ctx, group.ID)
	require.NoError(t, err)
	assert.Empty(t, grants, "the blocked group-role grant must not appear in storage")
}

// ── cli-rbac-002: last-global-admin lockout on the embedded group-role-removal path ──

// TestCliRbac002_RemoveRoleFromGroup_EnforcesLastAdminLockout proves that the
// embedded-mode `remove-role-from-group` CLI command still refuses to strand
// the install after #1395's fix routes it through
// core.KeyorixCore.RemoveRoleFromGroup instead of calling
// st.RemoveRoleFromGroup directly. Before the fix, removing a group's ONLY
// global admin-conferring role grant succeeded silently, leaving the
// deployment with no super_admin/admin/system_admin anywhere.
func TestCliRbac002_RemoveRoleFromGroup_EnforcesLastAdminLockout(t *testing.T) {
	require.NoError(t, i18n.InitializeForTesting()) // installAdminRoleIDSet's GetRoleByName("super_admin"/"system_admin") not-found path formats via i18n.T
	setupEmbeddedMode(t)
	t.Setenv("KEYORIX_CLI_ACTOR", "")

	st, err := common.InitializeStorage()
	require.NoError(t, err)
	ctx := context.Background()

	// "admin" is one of installAdminRoleNames (super_admin/admin/system_admin) —
	// a global-scope grant of it is install-admin-conferring.
	adminRole, err := st.CreateRole(ctx, mustFoldedName(t, "admin"), "Administrator")
	require.NoError(t, err)

	group, err := st.CreateGroup(ctx, &models.Group{Name: "sole-admin-group", NameFolded: "sole-admin-group"})
	require.NoError(t, err)

	// This is the deployment's ONLY global admin-tier grant: no other user or
	// group anywhere holds any install-admin role. Seeded directly via raw
	// storage (not through core) — this is fixture setup for the scenario, not
	// the mechanism under test.
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{}))

	origGroup, origRole, origProj, origEnv := removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag
	t.Cleanup(func() {
		removeGroupRoleGroupFlag, removeGroupRoleName, removeGroupRoleProjectFlag, removeGroupRoleEnvFlag = origGroup, origRole, origProj, origEnv
	})
	removeGroupRoleGroupFlag = "sole-admin-group"
	removeGroupRoleName = "admin"
	removeGroupRoleProjectFlag = ""
	removeGroupRoleEnvFlag = ""

	runErr := runRemoveRoleFromGroup(nil, nil)
	require.Error(t, runErr, "removing the install's last global admin-conferring group grant must be refused")
	assert.Contains(t, runErr.Error(), "no super_admin/admin/system_admin")

	// The grant must still be held.
	grants, err := st.GetGroupRoleGrants(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, grants, 1, "the last-admin group grant must still be held after the refused removal")
	assert.Equal(t, "admin", grants[0].Name)
}
