package services

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/require"
)

// Part 3 usage-based guard pass finding: gRPC AddGroupMember hardcoded
// actorIsMachine=false when calling core.AddUserToGroup, on the mistaken
// belief ("requireUser above guarantees a real human actor, never a
// machine") that a machine-authenticated caller could never reach this RPC.
// It can: the gRPC auth interceptor routes a machine token through the same
// UserContext path as a human session for every RPC including this one. The
// hardcoded false let a machine identity holding only roles.assign add a
// user to ANY group regardless of what roles that group confers, since
// AddUserToGroup's ceiling-check skip-gate (`actorID != 0 || actorIsMachine`)
// treated the machine caller (UserID==0, ADR-030) the same as no actor at
// all. Fixed by deriving actorIsMachine from actor.ActorKind() and tagging
// ctx with WithSelfMachineGranter so a genuinely-permissioned machine caller
// can still succeed.
func machineCtx(machineID uint) context.Context {
	return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
		&interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: machineID, Permissions: []string{"roles.assign"}})
}

// assignOnlyRole creates a role that bundles ONLY roles.assign -- enough to
// pass AddGroupMember's outer authorizeGlobal("roles.assign") gate, but
// nowhere near enough to satisfy requireGranterHoldsRolePermissions for a
// group conferring the far more privileged seeded "admin" role.
func assignOnlyRole(t *testing.T, h *testhelper.RBACTestHelper, roleID uint) uint {
	t.Helper()
	role := h.CreateTestRole(t, "grpc-machceiling-assign-only", "", roleID)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.assign'`, role.ID)
	return role.ID
}

func TestGroupService_AddGroupMember_MachineActorMissingRolePermissionsBlocked(t *testing.T) {
	svc, h := newGroupService(t)
	ctx := context.Background()

	target := h.CreateTestUser(t, "grpc-machceiling-target", 50)

	machine, err := h.CoreService.CreateMachineIdentity(ctx, 1, "grpc-machceiling-machine", core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "grpc-machceiling-admin-group"})
	require.NoError(t, err)

	assignOnlyID := assignOnlyRole(t, h, 100)
	adminRole, err := h.CoreService.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	// The machine holds only roles.assign (enough to pass the RPC's own outer
	// gate) -- nowhere near enough to satisfy the ceiling check for a group
	// conferring the seeded "admin" role's much larger permission bundle.
	require.NoError(t, h.CoreService.Storage().AssignMachineRole(ctx, machine.ID, assignOnlyID, storage.Scope{}))
	require.NoError(t, h.CoreService.Storage().AssignRoleToGroupWithExpiry(ctx, uint(g.GetId()), adminRole.ID, storage.Scope{}, time.Now().Add(time.Hour)))

	_, err = svc.AddGroupMember(machineCtx(machine.ID), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(target.ID)})
	require.Error(t, err, "a machine actor holding only roles.assign must be refused when the target group confers the seeded admin role, not silently succeed")
}

// Positive control: a machine actor that DOES hold the group's role's full
// permission set must still be allowed to add a member.
func TestGroupService_AddGroupMember_MachineActorHoldingRolePermissionsAllowed(t *testing.T) {
	svc, h := newGroupService(t)
	ctx := context.Background()

	target := h.CreateTestUser(t, "grpc-machceiling2-target", 51)

	machine, err := h.CoreService.CreateMachineIdentity(ctx, 1, "grpc-machceiling2-machine", core.MachineTypeService, "", "", 0, 0)
	require.NoError(t, err)

	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "grpc-machceiling2-admin-group"})
	require.NoError(t, err)

	adminRole, err := h.CoreService.Storage().GetRoleByName(ctx, "admin")
	require.NoError(t, err)
	require.NoError(t, h.CoreService.Storage().AssignMachineRole(ctx, machine.ID, adminRole.ID, storage.Scope{}))
	require.NoError(t, h.CoreService.Storage().AssignRoleToGroupWithExpiry(ctx, uint(g.GetId()), adminRole.ID, storage.Scope{}, time.Now().Add(time.Hour)))

	_, err = svc.AddGroupMember(machineCtx(machine.ID), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(target.ID)})
	require.NoError(t, err, "a machine actor holding the group's own role's full permission set must be allowed to add a member")
}
