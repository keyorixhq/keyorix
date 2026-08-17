// project_scoped_group_admin_guard_test.go — regression coverage for
// core-project-members.json#3 (groups.go:89): DeleteGroup / RemoveUserFromGroup
// (and their SCIM counterparts) previously only invoked the GLOBAL last-admin
// guard (guardLastGlobalAdminGroupDelete/Membership, #107) — a group holding a
// project's last roles.assign-conferring grant could be deleted, or have its
// last live member removed, with no guard at all, silently leaving that
// project with zero administrators. guardLastProjectAdminGroupDelete/
// Membership close that gap by generalizing guardLastProjectAdmin (the
// existing direct-user-removal guard, project_members.go) to the group path,
// mirroring guardLastGlobalAdminGroupDelete/Membership's own shape exactly.
package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteGroup_RefusesLastProjectAdmin(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u.ID, group.ID, 0))

	err = c.DeleteGroup(ctx, actor, group.ID)
	require.Error(t, err, "must refuse to delete a group holding project 7's last roles.assign grant")
	assert.Contains(t, err.Error(), "last administrative role grant")

	_, getErr := st.GetGroup(ctx, group.ID)
	require.NoError(t, getErr, "group must not have been deleted when the guard refuses")
}

func TestDeleteGroup_AllowsWhenAnotherProjectAdminExists(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true})
	require.NoError(t, err)
	other, err := st.CreateUser(ctx, &models.User{Username: "raj", Email: "raj@example.com", IsActive: true})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u.ID, group.ID, 0))
	// An independent, direct project_admin grant at the same project survives
	// the group's deletion.
	require.NoError(t, c.AddProjectMember(ctx, actor, proj, other.ID, "project_admin"))

	err = c.DeleteGroup(ctx, actor, group.ID)
	require.NoError(t, err, "deleting the group is fine when another project admin survives")
}

func TestDeleteGroup_AllowsWhenGroupHoldsNoProjectAdminRole(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	group, err := st.CreateGroup(ctx, &models.Group{Name: "engineering"})
	require.NoError(t, err)

	err = c.DeleteGroup(ctx, actor, group.ID)
	require.NoError(t, err, "deleting a group that confers no admin role at any scope must still work")
}

func TestDeleteGroup_RefusesWhenGroupAdminsMultipleProjects(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const projA, projB = uint(7), uint(8)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true})
	require.NoError(t, err)
	other, err := st.CreateUser(ctx, &models.User{Username: "raj", Email: "raj@example.com", IsActive: true})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "multi-proj-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: projA}))
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: projB}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u.ID, group.ID, 0))
	// projB has an independent survivor; projA does not.
	require.NoError(t, c.AddProjectMember(ctx, actor, projB, other.ID, "project_admin"))

	err = c.DeleteGroup(ctx, actor, group.ID)
	require.Error(t, err, "must refuse when even ONE of the group's administered projects would be left with no admin")
	assert.Contains(t, err.Error(), "last administrative role grant")
}

func TestRemoveUserFromGroup_RefusesLastProjectAdminMember(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u.ID, group.ID, 0))

	err = c.RemoveUserFromGroup(ctx, actor, u.ID, group.ID, 0)
	require.Error(t, err, "must refuse to remove the group's only member when that member is project 7's last admin route")
	assert.Contains(t, err.Error(), "last administrative role grant")

	members, mErr := st.ListGroupMembers(ctx, group.ID)
	require.NoError(t, mErr)
	require.Len(t, members, 1, "membership must not have been removed when the guard refuses")
}

func TestRemoveUserFromGroup_AllowsWhenAnotherGroupMemberSurvives(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u1, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true})
	require.NoError(t, err)
	u2, err := st.CreateUser(ctx, &models.User{Username: "raj", Email: "raj@example.com", IsActive: true})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u1.ID, group.ID, 0))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u2.ID, group.ID, 0))

	err = c.RemoveUserFromGroup(ctx, actor, u1.ID, group.ID, 0)
	require.NoError(t, err, "removing one of two group members is fine — the other still derives project-admin authority")

	members, mErr := st.ListGroupMembers(ctx, group.ID)
	require.NoError(t, mErr)
	require.Len(t, members, 1)
	assert.Equal(t, u2.ID, members[0].ID)
}

// TestDeprovisionSCIMGroup_RefusesLastProjectAdmin proves the SCIM path (which
// bypasses core.DeleteGroup entirely — see scim_groups.go's own inline guard
// calls) got the same project-scope fix, not just the native path.
func TestDeprovisionSCIMGroup_RefusesLastProjectAdmin(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	const proj = uint(7)
	const actor = uint(55)
	grantGlobalAdmin(t, st, actor)

	u, err := st.CreateUser(ctx, &models.User{Username: "priya", Email: "priya@example.com", IsActive: true, ExternalID: "okta|priya"})
	require.NoError(t, err)

	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	group, err := st.CreateGroup(ctx, &models.Group{Name: "scim-proj7-admins"})
	require.NoError(t, err)
	require.NoError(t, st.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{ProjectID: proj}))
	require.NoError(t, c.AddUserToGroup(ctx, actor, u.ID, group.ID, 0))

	err = c.DeprovisionSCIMGroup(ctx, actor, group.ID)
	require.Error(t, err, "SCIM group deprovisioning must also refuse to strip project 7's last admin route")

	_, getErr := st.GetGroup(ctx, group.ID)
	require.NoError(t, getErr, "group must not have been deleted when the guard refuses")
}
