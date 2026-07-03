package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #263: assignUserRole's existence check must treat an EXPIRED grant as absent, so a
// second real-incident activation (e.g. break-glass) for the same (user, role,
// project, environment) key succeeds instead of permanently failing with "already
// assigned" against a stale, un-reaped row. A genuinely still-live grant (no expiry,
// or an expiry still in the future) must continue to correctly block a duplicate.

// A permanent (non-expiring) grant still blocks a duplicate AssignRole.
func TestAssignRole_BlocksDuplicateOfLiveGrant(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	require.NoError(t, ls.AssignRole(ctx, 1, 10, sc(5, 0)))
	err := ls.AssignRole(ctx, 1, 10, sc(5, 0))
	require.Error(t, err, "a duplicate assignment of a permanent, still-live grant must be refused")
}

// A grant that has not yet expired still blocks a duplicate AssignRoleWithExpiry.
func TestAssignRoleWithExpiry_BlocksDuplicateOfLiveGrant(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	future := time.Now().Add(time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), future))

	err := ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), time.Now().Add(2*time.Hour))
	require.Error(t, err, "a duplicate assignment while the first grant is still live must be refused")
}

// The core of #263: once the FIRST grant's expires_at has naturally passed, a SECOND
// activation for the exact same (user, role, project, environment) key must succeed —
// not fail with "already assigned" against the stale, un-reaped row.
func TestAssignRoleWithExpiry_ReactivatesAfterNaturalExpiry(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), past),
		"seed a grant that is already expired at creation, simulating natural expiry")

	newExpiry := time.Now().Add(time.Hour)
	err := ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), newExpiry)
	require.NoError(t, err, "a second activation after the first grant naturally expired must succeed")

	ids, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Contains(t, ids, uint(10), "the fresh grant must be live and authorizing")
}

// Same as above but via the permanent AssignRole path re-granting after a PRIOR
// time-bound grant (e.g. AssignRoleWithExpiry) at the same key expired.
func TestAssignRole_SucceedsAfterPriorTimeBoundGrantExpired(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	require.NoError(t, ls.AssignRoleWithExpiry(ctx, 1, 10, sc(5, 0), past))

	err := ls.AssignRole(ctx, 1, 10, sc(5, 0))
	require.NoError(t, err, "a permanent re-grant after the prior time-bound grant expired must succeed")

	ids, err := ls.GetUserRoleIDsAt(ctx, 1, sc(5, 0))
	require.NoError(t, err)
	assert.Contains(t, ids, uint(10))
}

// #374/#375/#376: GetUserPermissions and CheckPermission previously joined ONLY
// user_roles (direct assignments), leaving them blind to a permission granted
// purely via a group role — unlike the live authorization path (scopedRoleIDs,
// authz.go), which correctly unions direct and group-inherited roles. These
// tests pin the fix: a permission held ONLY through group membership must now
// be visible.
func TestGetUserPermissions_DirectOnly_DoesNotIncludeGroupGrant(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	seedGroupGrantedPermission(t, ls)

	// GetUserPermissions is documented as direct-only; the group-derived
	// permission must NOT appear here (GetUserGroupPermissions is its
	// counterpart — callers needing the full effective set must union both).
	perms, err := ls.GetUserPermissions(ctx, 1)
	require.NoError(t, err)
	assert.Empty(t, perms, "a permission granted only via a group role is not direct")
}

func TestGetUserGroupPermissions_IncludesGroupDerivedPermission(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	seedGroupGrantedPermission(t, ls)

	perms, err := ls.GetUserGroupPermissions(ctx, 1)
	require.NoError(t, err)
	require.Len(t, perms, 1)
	assert.Equal(t, "secrets.admin", perms[0].Name)
}

// CheckPermission must find a permission granted purely via a group role — the
// storage-layer #376 axis: it previously joined only user_roles, so a group-only
// grant read as "does NOT have permission" even though Authorize() genuinely
// grants it.
func TestCheckPermission_IncludesGroupDerivedPermission(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	seedGroupGrantedPermission(t, ls)

	has, err := ls.CheckPermission(ctx, 1, "secrets", "admin")
	require.NoError(t, err)
	assert.True(t, has, "a permission granted only via a group role must be found")

	has, err = ls.CheckPermission(ctx, 1, "secrets", "write")
	require.NoError(t, err)
	assert.False(t, has, "an unrelated permission must not be reported as held")
}

// A soft-deleted group must confer no permission, mirroring
// GetUserGroupRoleIDsAt's own soft-delete gate.
func TestCheckPermission_SoftDeletedGroupConfersNothing(t *testing.T) {
	ls := newRBACScopeTestStore(t)
	ctx := context.Background()
	seedGroupGrantedPermission(t, ls)

	require.NoError(t, ls.db.Delete(&models.Group{}, 100).Error)

	has, err := ls.CheckPermission(ctx, 1, "secrets", "admin")
	require.NoError(t, err)
	assert.False(t, has, "a soft-deleted group's grant must stop authorizing")
}

// seedGroupGrantedPermission puts user 1 in group 100, which holds role 50
// globally, which is bundled with permission secrets.admin — i.e. user 1 holds
// secrets.admin PURELY via group membership, no direct role.
func seedGroupGrantedPermission(t *testing.T, ls *LocalStorage) {
	t.Helper()
	require.NoError(t, ls.db.Create(&models.Role{ID: 50, Name: "group-role"}).Error)
	require.NoError(t, ls.db.Create(&models.Permission{ID: 1, Name: "secrets.admin", Resource: "secrets", Action: "admin"}).Error)
	require.NoError(t, ls.db.Create(&models.RolePermission{RoleID: 50, PermissionID: 1}).Error)
	require.NoError(t, ls.db.Create(&models.Group{ID: 100, Name: "g100"}).Error)
	require.NoError(t, ls.db.Create(&models.UserGroup{UserID: 1, GroupID: 100}).Error)
	require.NoError(t, ls.db.Create(&models.GroupRole{GroupID: 100, RoleID: 50, ProjectID: 0, EnvironmentID: 0}).Error)
}
