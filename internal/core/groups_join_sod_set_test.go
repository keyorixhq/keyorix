package core_test

// groups_join_sod_set_test.go — #G05 / findings-core/core-project-members.json#4:
// validateGroupJoinRoles (groups.go) used to check a group's role grants ONE AT A
// TIME via requireNoSoDViolation, each call comparing a single new role's
// permissions against what the user held BEFORE the join. That per-role shape
// structurally cannot catch a violation that only exists because two of the
// GROUP'S OWN roles combine with each other — neither role's individual
// permission set, checked in isolation, ever includes the other new role's
// permissions in the same pass. Fixed by requireGroupJoinNoSoDViolation (sod.go),
// which evaluates the group's FULL role set against the user's current holdings
// in one pass, mirroring requireGrantSetNoSoDViolation's set-based shape.

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedIsolatedRole creates a role that grants EXACTLY ONE permission (as
// opposed to the shared fixture roles, e.g. "editor", which bundle several) so
// a test can isolate whether a single role or a role COMBINATION is what
// triggers an SoD policy.
func seedIsolatedRole(t *testing.T, h *testhelper.RBACTestHelper, roleName, permName string, roleID uint) {
	t.Helper()
	h.CreateTestRole(t, roleName, "", roleID)
	h.ExecuteRawSQL(t, `INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r, permissions p WHERE r.name = ? AND p.name = ?`, roleName, permName)
}

// TestAddUserToGroup_BlocksSoDViolationAcrossGroupRoleSet is the core
// regression: the group itself grants TWO roles together (neither the user's
// pre-existing holdings — there are none — nor either role alone completes the
// policy), and only the COMBINATION does. The old per-role loop checked each
// grant against the user's pre-join permissions independently and missed this
// entirely; joining must now be refused.
func TestAddUserToGroup_BlocksSoDViolationAcrossGroupRoleSet(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	seedIsolatedRole(t, h, "combo_read_only", "secrets.read", 70)
	seedIsolatedRole(t, h, "combo_write_only", "secrets.write", 71)

	h.CreateTestUser(t, "mallory", 70) // no pre-existing roles at all

	h.CreateTestGroup(t, "combo-group", "", 50)
	h.AssignGroupRole(t, 50, 70, nil) // combo_read_only
	h.AssignGroupRole(t, 50, 71, nil) // combo_write_only — combined with the
	// above, this is the toxic pair; neither role alone carries both sides.

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	// actorID 71 is an arbitrary non-zero, non-privileged actor: neither
	// combo_read_only nor combo_write_only is an admin-tier role name, so
	// requireAuthorityForRole imposes no ceiling here — only the SoD gate under
	// test is exercised.
	err = h.CoreService.AddUserToGroup(ctx, 71, 70, 50, 0)
	require.Error(t, err, "joining a group whose OWN role grants combine into a toxic pair must be refused")
	assert.Contains(t, err.Error(), "separation-of-duties")

	groups, gerr := h.Storage.GetUserGroups(ctx, 70)
	require.NoError(t, gerr)
	for _, g := range groups {
		assert.NotEqual(t, uint(50), g.ID, "the blocked membership must not have been persisted")
	}
}

// TestAddUserToGroup_BlocksSoDViolationWithExistingRole covers the scenario
// named in the finding directly: a principal ALREADY holds role A (via a
// direct grant), and the group grants a single new role B, where {A, B} is a
// forbidden pair. This one is refused even under the old per-role check (its
// single requireNoSoDViolation call already compared the new role against the
// user's pre-join holdings correctly) — kept as an explicit non-regression
// pin for the scenario the finding calls out, alongside the set-combination
// gap above that the old code actually missed.
func TestAddUserToGroup_BlocksSoDViolationWithExistingRole(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	seedIsolatedRole(t, h, "existing_read_only", "secrets.read", 72)
	seedIsolatedRole(t, h, "existing_write_only", "secrets.write", 73)

	h.CreateTestUser(t, "oscar", 72)
	h.AssignUserRole(t, 72, 72, nil) // existing_read_only, held directly beforehand

	h.CreateTestGroup(t, "existing-group", "", 51)
	h.AssignGroupRole(t, 51, 73, nil) // existing_write_only

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	err = h.CoreService.AddUserToGroup(ctx, 73, 72, 51, 0)
	require.Error(t, err, "joining a group that grants a role completing a policy with an already-held role must be refused")
	assert.Contains(t, err.Error(), "separation-of-duties")
}

// TestAddUserToGroup_AllowsNonViolatingGroupJoin is the negative control: a
// group whose role grants do NOT combine (with each other or with anything
// the user already holds) to complete any SoD policy must still let the user
// join normally — the new set-based check must not be overbroad.
func TestAddUserToGroup_AllowsNonViolatingGroupJoin(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	require.NoError(t, h.DB.AutoMigrate(&models.SoDPolicy{}, &models.AuditEvent{}))
	ctx := context.Background()

	seedIsolatedRole(t, h, "safe_read_only", "secrets.read", 74)
	seedIsolatedRole(t, h, "safe_other_only", "users.read", 75)

	h.CreateTestUser(t, "peggy", 74)

	h.CreateTestGroup(t, "safe-group", "", 52)
	h.AssignGroupRole(t, 52, 74, nil) // safe_read_only
	h.AssignGroupRole(t, 52, 75, nil) // safe_other_only — no policy pairs these

	_, err := h.CoreService.CreateSoDPolicy(ctx, 1, "read-vs-write", "", "secrets.read", "secrets.write")
	require.NoError(t, err)

	err = h.CoreService.AddUserToGroup(ctx, 75, 74, 52, 0)
	require.NoError(t, err, "a non-violating group join must succeed unimpeded")

	groups, gerr := h.Storage.GetUserGroups(ctx, 74)
	require.NoError(t, gerr)
	var found bool
	for _, g := range groups {
		if g.ID == 52 {
			found = true
		}
	}
	assert.True(t, found, "the membership must have been persisted")
}
