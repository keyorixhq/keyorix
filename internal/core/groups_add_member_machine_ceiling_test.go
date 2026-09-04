package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Part 3 usage-based guard pass finding: AddUserToGroup's own ceiling-check
// wiring (validateGroupJoinRoles -> requireGranterHoldsRolePermissions,
// gated by the outer `actorID != 0 || actorIsMachine` skip at groups.go:260)
// is correct given correct inputs -- these three tests pin that down, mirroring
// authz_machine_granter_ceiling_test.go's AssignMachineRole pattern exactly.
// The actual regression this pass found was NOT here: it was two callers
// (server/grpc/services/group_service.go's AddGroupMember and
// server/http/handlers/groups_members.go's AddGroupMember) hardcoding
// actorIsMachine=false regardless of the real caller's actor kind -- see the
// handler/service-level tests alongside those files for the caller-side fix.
func TestAddUserToGroup_MachineGranterHoldingRolePermissionsAllowed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "group-granter", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "group-target", Email: "group-target@example.com", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	grp, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "ceiling-test-group"})
	require.NoError(t, err)

	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	// Seed the granter's own permissions AND the group's role directly at the
	// storage layer, bypassing the ceiling check itself for test setup (same
	// pattern authz_machine_granter_ceiling_test.go uses).
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, devRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRoleToGroupWithExpiry(ctx, grp.ID, devRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	grantCtx := WithSelfMachineGranter(ctx, granter.ID)
	err = c.AddUserToGroup(grantCtx, 0, true, target.ID, grp.ID, 1)
	require.NoError(t, err, "a machine granter that already holds every permission the group's role bundles must be allowed to add a member")
}

func TestAddUserToGroup_MachineGranterMissingRolePermissionsBlocked(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "group-granter2", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "group-target2", Email: "group-target2@example.com", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	grp, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "ceiling-test-group2"})
	require.NoError(t, err)

	viewerRole, err := st.GetRoleByName(ctx, "project_viewer")
	require.NoError(t, err)
	adminRole, err := st.GetRoleByName(ctx, "project_admin")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, viewerRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRoleToGroupWithExpiry(ctx, grp.ID, adminRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	grantCtx := WithSelfMachineGranter(ctx, granter.ID)
	err = c.AddUserToGroup(grantCtx, 0, true, target.ID, grp.ID, 1)
	require.Error(t, err, "a machine granter holding only project_viewer must not be able to add a member to a group conferring project_admin")
	assert.Contains(t, err.Error(), "cannot grant this role")
}

// actorIsMachine set but ctx carries no WithSelfMachineGranter tag must fail
// closed -- this is the exact invariant the two caller-side bugs this pass
// found would have silently defeated had AddUserToGroup's OWN gating been
// wrong too (it wasn't; the bug was in the callers never reaching this
// codepath with actorIsMachine=true at all).
func TestAddUserToGroup_MachineGranterUntaggedContextFailsClosed(t *testing.T) {
	c, st := newBootstrappedCore(t)
	ctx := context.Background()

	granter, err := c.CreateMachineIdentity(ctx, 1, "group-granter3", MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)
	target, err := c.CreateUser(ctx, &CreateUserRequest{
		Username: "group-target3", Email: "group-target3@example.com", Password: "Kx#Vr9$Mn2!Zp4@Qw",
	})
	require.NoError(t, err)
	grp, err := c.CreateGroup(ctx, 1, &CreateGroupRequest{Name: "ceiling-test-group3"})
	require.NoError(t, err)

	devRole, err := st.GetRoleByName(ctx, "project_developer")
	require.NoError(t, err)
	require.NoError(t, st.AssignMachineRole(ctx, granter.ID, devRole.ID, storage.Scope{ProjectID: 1}))
	require.NoError(t, st.AssignRoleToGroupWithExpiry(ctx, grp.ID, devRole.ID, storage.Scope{ProjectID: 1}, time.Now().Add(time.Hour)))

	err = c.AddUserToGroup(ctx, 0, true, target.ID, grp.ID, 1)
	require.Error(t, err, "actorIsMachine=true with no WithSelfMachineGranter tag must fail closed, not silently pass")
	assert.Contains(t, err.Error(), "cannot grant this role")
}
