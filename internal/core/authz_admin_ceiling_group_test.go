package core

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// #93/#107 — the admin-rank ceiling must gate every path that can confer an admin
// role, not just the invitation/membership flows: direct project-member grants,
// machine-role grants, and group role/membership grants (joining an
// admin-conferring group inherits its access just as directly as a role grant).
// AddProjectMember/SetProjectMemberRole funnel through AssignUserRole, so their
// ceiling is requireGranterHoldsRolePermissions (#93/#107/#141: the actor must
// already hold every permission the role bundles); AssignMachineRole/
// AssignRoleToGroup/AssignGroupRoleWithExpiry/AddUserToGroup are gated directly by
// requireAuthorityForRole (the actor must hold an admin-tier role). These tests pin
// the escalation-by-proxy fix on each entry point, plus the last-install-
// administrator invariant on the group removal paths.

// #93: AddProjectMember must refuse a non-admin actor granting an admin role.
func TestAddProjectMember_EscalationByProxyBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "pm-attacker", "project_viewer", storage.Scope{ProjectID: 1})
	victim := seedUserWithRole(t, st, "pm-victim", "project_viewer", storage.Scope{ProjectID: 1})

	err := c.AddProjectMember(ctx, attacker, 1, victim, "admin")
	require.Error(t, err, "a non-admin actor must not be able to grant the admin role directly")
	assert.Contains(t, err.Error(), "cannot grant this role")
}

// #93: AddProjectMember still works for a non-admin role the actor already holds
// every bundled permission of (the common case). The actor holds project_developer
// itself, so requireGranterHoldsRolePermissions (#93/#107/#141) is trivially
// satisfied granting that same role to someone else — this isn't an escalation.
func TestAddProjectMember_NonAdminRoleAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	actor := seedUserWithRole(t, st, "pm-actor", "project_developer", storage.Scope{ProjectID: 1})
	victim := seedUserWithRole(t, st, "pm-victim2", "project_viewer", storage.Scope{ProjectID: 2})

	require.NoError(t, c.AddProjectMember(ctx, actor, 1, victim, "project_developer"))
}

// #93: SetProjectMemberRole must refuse a non-admin actor upgrading a member to
// an admin role.
func TestSetProjectMemberRole_EscalationByProxyBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "smr-attacker", "project_viewer", storage.Scope{ProjectID: 1})
	victim := seedUserWithRole(t, st, "smr-victim", "project_viewer", storage.Scope{ProjectID: 1})

	err := c.SetProjectMemberRole(ctx, attacker, 1, victim, "project_admin")
	require.Error(t, err, "a non-admin actor must not be able to promote a member to project_admin")
	assert.Contains(t, err.Error(), "cannot grant this role")
}

// #93: AssignMachineRole must refuse a non-admin actor granting an admin role to
// a machine identity.
func TestAssignMachineRole_EscalationByProxyBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "mr-attacker", "project_viewer", storage.Scope{ProjectID: 1})
	m, err := c.CreateMachineIdentity(ctx, 1, "svc", MachineTypeService, "", "", attacker)
	require.NoError(t, err)
	adminRole, err := c.storage.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)

	err = c.AssignMachineRole(ctx, m.ID, adminRole.ID, Scope{ProjectID: 1}, attacker)
	require.Error(t, err, "a non-admin actor must not be able to grant an admin role to a machine identity")
	assert.Contains(t, err.Error(), "administrator")
}

// #107: joining an admin-conferring group must be gated by the same
// escalation-by-proxy ceiling as a direct role grant — otherwise a non-admin
// roles.assign holder self-escalates by joining the group instead of being
// granted the role.
func TestAddUserToGroup_EscalationByProxyBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "grp-attacker", "project_viewer", storage.Scope{ProjectID: 1})

	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "admins"})
	require.NoError(t, err)
	require.NoError(t, c.storage.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{}))

	err = c.AddUserToGroup(ctx, attacker, attacker, group.ID, 0)
	require.Error(t, err, "a non-admin actor must not be able to join an admin-conferring group")
	assert.Contains(t, err.Error(), "administrator")
}

// #107 positive control: an admin actor CAN add a member to an admin-conferring
// group, and the local-CLI (actorID 0) convention is exempt from the ceiling.
func TestAddUserToGroup_AdminActorAndLocalCLIAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	admin := seedUserWithRole(t, st, "grp-admin", "admin", storage.Scope{})
	victim := seedUserWithRole(t, st, "grp-victim", "project_viewer", storage.Scope{ProjectID: 1})

	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "admins2"})
	require.NoError(t, err)
	require.NoError(t, c.storage.AssignRoleToGroup(ctx, group.ID, adminRole.ID, storage.Scope{}))

	require.NoError(t, c.AddUserToGroup(ctx, admin, victim, group.ID, 0))
	members, err := c.GetGroupMembers(ctx, group.ID)
	require.NoError(t, err)
	require.Len(t, members, 1)

	// Local CLI (actorID 0) is exempt — it can already self-grant any role via
	// AssignRoleToUser, so gating it here would only add friction, not security.
	group2, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "admins3"})
	require.NoError(t, err)
	require.NoError(t, c.storage.AssignRoleToGroup(ctx, group2.ID, adminRole.ID, storage.Scope{}))
	require.NoError(t, c.AddUserToGroup(ctx, 0, victim, group2.ID, 0))
}

// #107: AssignRoleToGroup must refuse a non-admin actor granting an admin role
// to a group.
func TestAssignRoleToGroup_EscalationByProxyBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	attacker := seedUserWithRole(t, st, "artg-attacker", "project_viewer", storage.Scope{ProjectID: 1})
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "g1"})
	require.NoError(t, err)
	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	err = c.AssignRoleToGroup(ctx, attacker, group.ID, adminRole.ID, Scope{})
	require.Error(t, err, "a non-admin actor must not be able to grant a group the admin role")
	assert.Contains(t, err.Error(), "administrator")
}

// #107: RemoveRoleFromGroup must refuse to strip the install's last global-admin
// path when the group is the sole remaining source.
func TestRemoveRoleFromGroup_LastGlobalAdminBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	// Make a group the SOLE global-admin source: give it the admin role, then
	// strip the bootstrap admin's own direct grant.
	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "sole-admins"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, bootstrapAdmin.ID, group.ID, adminRole.ID, Scope{}))
	require.NoError(t, c.RemoveUserRole(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, adminRole.ID, Scope{}))

	err = c.RemoveRoleFromGroup(ctx, bootstrapAdmin.ID, group.ID, adminRole.ID, Scope{})
	require.Error(t, err, "removing the group's grant would leave the install with no global admin")
	assert.Contains(t, err.Error(), "no super_admin/admin/system_admin")
}

// #107: DeleteGroup must refuse to delete a group that is the install's last
// global-admin source.
func TestDeleteGroup_LastGlobalAdminBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "sole-admins2"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, bootstrapAdmin.ID, group.ID, adminRole.ID, Scope{}))
	require.NoError(t, c.RemoveUserRole(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, adminRole.ID, Scope{}))

	err = c.DeleteGroup(ctx, bootstrapAdmin.ID, group.ID)
	require.Error(t, err, "deleting the group would leave the install with no global admin")
	assert.Contains(t, err.Error(), "last administrative role grant")
}

// #107: RemoveUserFromGroup must refuse to remove the last LIVE member of an
// admin-conferring group when no other path gives the install a global admin —
// even though the role grant itself survives the membership removal.
func TestRemoveUserFromGroup_LastMemberBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "sole-admins3"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, bootstrapAdmin.ID, group.ID, adminRole.ID, Scope{}))
	require.NoError(t, c.AddUserToGroup(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, group.ID, 0))
	require.NoError(t, c.RemoveUserRole(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, adminRole.ID, Scope{}))

	// bootstrapAdmin is now the group's only member and the install's only
	// global-admin path runs through it.
	err = c.RemoveUserFromGroup(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, group.ID, 0)
	require.Error(t, err, "removing the group's last member would leave no one able to manage the install")
	assert.Contains(t, err.Error(), "last administrator")
}

// #107 positive control: removing a member is fine when another live admin path
// (here, a second member of the same group) survives.
func TestRemoveUserFromGroup_OtherMemberSurvivesAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	bootstrapAdmin, err := st.GetUserByEmail(ctx, "admin@example.com")
	require.NoError(t, err)
	second := seedUserWithRole(t, st, "grp-second", "project_viewer", storage.Scope{ProjectID: 1})
	adminRole, err := c.storage.GetRoleByName(ctx, "admin")
	require.NoError(t, err)

	group, err := c.CreateGroup(ctx, 0, &CreateGroupRequest{Name: "two-admins"})
	require.NoError(t, err)
	require.NoError(t, c.AssignRoleToGroup(ctx, bootstrapAdmin.ID, group.ID, adminRole.ID, Scope{}))
	require.NoError(t, c.AddUserToGroup(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, group.ID, 0))
	require.NoError(t, c.AddUserToGroup(ctx, bootstrapAdmin.ID, second, group.ID, 0))
	require.NoError(t, c.RemoveUserRole(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, adminRole.ID, Scope{}))

	require.NoError(t, c.RemoveUserFromGroup(ctx, bootstrapAdmin.ID, bootstrapAdmin.ID, group.ID, 0),
		"the second group member keeps the install's admin access live")
}
