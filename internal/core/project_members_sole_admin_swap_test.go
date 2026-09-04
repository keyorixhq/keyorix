package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/identity"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FIX-2 (Part 2 regression audit): swapping the project's SOLE administrator
// directly from one admin-tier (roles.assign-carrying) role to ANOTHER must
// succeed. RemoveUserRole's own project-scope last-admin guard (added by the
// original FIX-2, rbac_management.go) used to re-derive "after" as "existing
// roles minus the one being removed", blind to the compensating AssignUserRole
// SetProjectMemberRole makes immediately afterward within the SAME atomic,
// WithNamedLock-protected operation -- so a sole admin's role swap was
// falsely refused as if it left the project ungoverned, even though
// SetProjectMemberRole's OWN upfront guardLastProjectAdmin call (using the
// true before/after state) had already confirmed it does not.
func TestSetProjectMemberRole_SoleAdminSwapBetweenTwoAdminRolesAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	perms, err := c.ListPermissions(ctx)
	require.NoError(t, err)
	var rolesAssignID uint
	for _, p := range perms {
		if p.Name == "roles.assign" {
			rolesAssignID = p.ID
		}
	}
	require.NotZero(t, rolesAssignID, "roles.assign must be seeded")

	roleAName, err := identity.NewFoldedName("sole-admin-swap-role-a")
	require.NoError(t, err)
	roleA, err := st.CreateRole(ctx, roleAName, "admin-tier role A")
	require.NoError(t, err)
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, roleA.ID, rolesAssignID, false))

	roleBName, err := identity.NewFoldedName("sole-admin-swap-role-b")
	require.NoError(t, err)
	roleB, err := st.CreateRole(ctx, roleBName, "admin-tier role B")
	require.NoError(t, err)
	require.NoError(t, c.AssignPermissionToRole(ctx, 0, roleB.ID, rolesAssignID, false))

	u, err := st.CreateUser(ctx, &models.User{Username: "sole-admin", Email: "sole-admin@example.com", IsActive: true})
	require.NoError(t, err)
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, u.ID, "sole-admin-swap-role-a", false))

	err = c.SetProjectMemberRole(ctx, actor, proj, u.ID, "sole-admin-swap-role-b", false)
	require.NoError(t, err, "swapping the sole admin directly between two admin-tier roles must not be refused as a last-admin violation")

	members, err := c.ListProjectMembers(ctx, proj)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "sole-admin-swap-role-b", members[0].RoleName)
}
