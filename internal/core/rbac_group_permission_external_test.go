package core_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #375: GetUserPermissionsByID is the "what can this user do" view behind the
// dashboard/access-review endpoint (GET /api/v1/users/{id}/permissions). It
// previously reported only DIRECT role grants — a permission held purely via a
// group role was invisible to a reviewer even though Authorize() genuinely
// grants it on every live request. This pins the fix: the union of direct AND
// group-derived permissions.
func TestGetUserPermissionsByID_IncludesGroupDerivedPermission(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	// gina holds viewer (secrets.read, users.read) DIRECTLY, and editor
	// (secrets.write) ONLY via a group.
	h.CreateTestUser(t, "gina", 20)
	h.AssignUserRole(t, 20, 4, nil) // viewer (direct)
	h.CreateTestGroup(t, "writers", "secrets writers", 40)
	h.AssignGroupRole(t, 40, 3, nil) // group carries editor → secrets.write
	h.AssignUserToGroup(t, 20, 40)

	perms, err := h.CoreService.GetUserPermissionsByID(ctx, 20)
	require.NoError(t, err)

	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, "secrets.read", "direct viewer permission must still be present")
	assert.Contains(t, names, "secrets.write", "group-derived editor permission must now be visible")

	// De-duplication: a permission held both directly and via a group (e.g.
	// secrets.read, granted by both viewer directly and — indirectly — nothing
	// else here) must not be duplicated. Verify no name repeats.
	seen := map[string]bool{}
	for _, n := range names {
		assert.False(t, seen[n], "permission %q must not be duplicated", n)
		seen[n] = true
	}
}

// A user with no group membership at all still gets exactly their direct set —
// the fix must not fabricate permissions for a user with no groups.
func TestGetUserPermissionsByID_NoGroups_DirectOnly(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	h.CreateTestUser(t, "henry", 21)
	h.AssignUserRole(t, 21, 4, nil) // viewer only, no groups

	perms, err := h.CoreService.GetUserPermissionsByID(ctx, 21)
	require.NoError(t, err)

	names := make([]string, 0, len(perms))
	for _, p := range perms {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, "secrets.read")
	assert.Contains(t, names, "users.read")
	assert.NotContains(t, names, "secrets.write")
}

// #376: HasPermissionByEmail (the CLI `check-permission` diagnostic used for
// offboarding/incident-response) previously delegated to a raw, scope-blind,
// group-blind, admin-bypass-blind storage query. It now delegates to Authorize
// (mirroring scopedRoleIDs) per scope, so it must agree with Authorize on all
// three axes that had drifted.
func TestHasPermissionByEmail_GroupDerivedPermission(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	h.CreateTestUser(t, "iris", 22)
	h.CreateTestGroup(t, "writers", "secrets writers", 41)
	h.AssignGroupRole(t, 41, 3, nil) // group carries editor → secrets.write
	h.AssignUserToGroup(t, 22, 41)

	ok, err := h.CoreService.HasPermissionByEmail(ctx, "iris@test.com", "secrets", "write")
	require.NoError(t, err)
	assert.True(t, ok, "a permission granted only via a group role must be found")

	ok, err = h.CoreService.HasPermissionByEmail(ctx, "iris@test.com", "secrets", "delete")
	require.NoError(t, err)
	assert.False(t, ok, "a permission the user does not hold at all must read as false")
}

// A super_admin with no explicit role_permissions row for the checked
// permission must still read as "has permission" — Authorize's admin-role
// bypass applies. Before the fix this read as a false "does NOT have
// permission", exactly the false-negative the finding describes.
func TestHasPermissionByEmail_AdminBypass(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	h.CreateTestUser(t, "jack", 23)
	h.AssignUserRole(t, 23, 1, nil) // super_admin, global

	// A permission NOT in the seeded super_admin role_permissions set at all.
	ok, err := h.CoreService.HasPermissionByEmail(ctx, "jack@test.com", "connect", "write")
	require.NoError(t, err)
	assert.True(t, ok, "a super_admin bypasses the per-permission check even for an unlisted permission")
}

// A grant scoped to a since-soft-deleted project must stop authorizing, exactly
// like Authorize()/scopedRoleIDs — the storage-blind old query ignored scope
// validity entirely and would have kept reporting "has permission" regardless.
func TestHasPermissionByEmail_ScopeRestrictedAssignment_DeletedProjectStopsAuthorizing(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	h.CreateTestUser(t, "kate", 24)
	projID := uint(2) // "production" project, seeded by the helper
	h.AssignUserRole(t, 24, 3, &projID) // editor, scoped to project 2 → secrets.write

	ok, err := h.CoreService.HasPermissionByEmail(ctx, "kate@test.com", "secrets", "write")
	require.NoError(t, err)
	assert.True(t, ok, "a live project-scoped grant authorizes")

	require.NoError(t, h.DB.Delete(&models.Project{}, projID).Error)

	ok, err = h.CoreService.HasPermissionByEmail(ctx, "kate@test.com", "secrets", "write")
	require.NoError(t, err)
	assert.False(t, ok, "a grant scoped to a soft-deleted project must stop authorizing")
}

// A user with no role grants at all (no scope to iterate) must read as false,
// not error — Authorize's own "no roles, no permission" resolution at the
// global scope.
func TestHasPermissionByEmail_NoGrantsAtAll(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	defer h.Cleanup()
	ctx := context.Background()

	h.CreateTestUser(t, "liam", 25)

	ok, err := h.CoreService.HasPermissionByEmail(ctx, "liam@test.com", "secrets", "read")
	require.NoError(t, err)
	assert.False(t, ok)
}
