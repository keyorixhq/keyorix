// local_rbac_zero_coverage_test.go covers local_rbac.go functions that were
// still at 0%: SetRoleBypassesPermissionChecks, RoleSetBypassesPermissionChecks,
// IsGroupProjectScoped, ListAllGroupRoleGrants, ListAllUserRoleGrants.
package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetRoleBypassesPermissionChecks(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()
	name, err := identity.NewFoldedName("bypasser")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, name, "bypasses checks")
	require.NoError(t, err)
	assert.False(t, role.BypassesPermissionChecks)

	require.NoError(t, ls.SetRoleBypassesPermissionChecks(ctx, role.ID, true))
	got, err := ls.GetRole(ctx, role.ID)
	require.NoError(t, err)
	assert.True(t, got.BypassesPermissionChecks)

	require.NoError(t, ls.SetRoleBypassesPermissionChecks(ctx, role.ID, false))
	got, err = ls.GetRole(ctx, role.ID)
	require.NoError(t, err)
	assert.False(t, got.BypassesPermissionChecks)
}

func TestRoleSetBypassesPermissionChecks(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()

	nameA, err := identity.NewFoldedName("role-a")
	require.NoError(t, err)
	roleA, err := ls.CreateRole(ctx, nameA, "a")
	require.NoError(t, err)

	nameB, err := identity.NewFoldedName("role-b")
	require.NoError(t, err)
	roleB, err := ls.CreateRole(ctx, nameB, "b")
	require.NoError(t, err)

	bypasses, err := ls.RoleSetBypassesPermissionChecks(ctx, []uint{roleA.ID, roleB.ID})
	require.NoError(t, err)
	assert.False(t, bypasses, "neither role bypasses yet")

	require.NoError(t, ls.SetRoleBypassesPermissionChecks(ctx, roleB.ID, true))
	bypasses, err = ls.RoleSetBypassesPermissionChecks(ctx, []uint{roleA.ID, roleB.ID})
	require.NoError(t, err)
	assert.True(t, bypasses, "at least one role in the set bypasses")

	bypasses, err = ls.RoleSetBypassesPermissionChecks(ctx, nil)
	require.NoError(t, err)
	assert.False(t, bypasses, "an empty role set never bypasses")
}

func TestIsGroupProjectScoped(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()

	name, err := identity.NewFoldedName("scoped-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, name, "scoped")
	require.NoError(t, err)

	group, err := ls.CreateGroup(ctx, &models.Group{Name: "scoped-group", NameFolded: "scoped-group"})
	require.NoError(t, err)

	// projectID == 0 short-circuits to false without querying.
	scoped, err := ls.IsGroupProjectScoped(ctx, group.ID, 0)
	require.NoError(t, err)
	assert.False(t, scoped)

	// No grant yet at project 7.
	scoped, err = ls.IsGroupProjectScoped(ctx, group.ID, 7)
	require.NoError(t, err)
	assert.False(t, scoped)

	require.NoError(t, ls.AssignRoleToGroup(ctx, group.ID, role.ID, storage.Scope{ProjectID: 7}))

	scoped, err = ls.IsGroupProjectScoped(ctx, group.ID, 7)
	require.NoError(t, err)
	assert.True(t, scoped)

	// A different project must not be considered scoped.
	scoped, err = ls.IsGroupProjectScoped(ctx, group.ID, 8)
	require.NoError(t, err)
	assert.False(t, scoped)
}

// An expired group-role grant must not count as project-scoping.
func TestIsGroupProjectScoped_ExpiredGrantExcluded(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()

	name, err := identity.NewFoldedName("scoped-role-2")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, name, "scoped")
	require.NoError(t, err)
	group, err := ls.CreateGroup(ctx, &models.Group{Name: "scoped-group-2", NameFolded: "scoped-group-2"})
	require.NoError(t, err)

	require.NoError(t, ls.AssignRoleToGroupWithExpiry(ctx, group.ID, role.ID, storage.Scope{ProjectID: 9}, time.Now().Add(-time.Hour)))

	scoped, err := ls.IsGroupProjectScoped(ctx, group.ID, 9)
	require.NoError(t, err)
	assert.False(t, scoped, "an expired grant must not count as project scoping")
}

func TestListAllGroupRoleGrants(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()

	grants, err := ls.ListAllGroupRoleGrants(ctx)
	require.NoError(t, err)
	assert.Empty(t, grants)

	name, err := identity.NewFoldedName("gr-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, name, "x")
	require.NoError(t, err)
	group, err := ls.CreateGroup(ctx, &models.Group{Name: "gr-group", NameFolded: "gr-group"})
	require.NoError(t, err)
	require.NoError(t, ls.AssignRoleToGroup(ctx, group.ID, role.ID, storage.Scope{ProjectID: 1}))

	grants, err = ls.ListAllGroupRoleGrants(ctx)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, group.ID, grants[0].GroupID)
	assert.Equal(t, role.ID, grants[0].RoleID)
}

func TestListAllUserRoleGrants(t *testing.T) {
	ls := newRBACStore(t)
	ctx := context.Background()

	grants, err := ls.ListAllUserRoleGrants(ctx)
	require.NoError(t, err)
	assert.Empty(t, grants)

	name, err := identity.NewFoldedName("ur-role")
	require.NoError(t, err)
	role, err := ls.CreateRole(ctx, name, "x")
	require.NoError(t, err)
	user, err := ls.CreateUser(ctx, &models.User{
		Username: "ur-user", UsernameFolded: "ur-user", Email: "ur-user@example.com", EmailFolded: "ur-user@example.com",
	})
	require.NoError(t, err)

	require.NoError(t, ls.AssignRole(ctx, user.ID, role.ID, storage.Scope{ProjectID: 1}))

	grants, err = ls.ListAllUserRoleGrants(ctx)
	require.NoError(t, err)
	require.Len(t, grants, 1)
	assert.Equal(t, user.ID, grants[0].UserID)
	assert.Equal(t, role.ID, grants[0].RoleID)
}
