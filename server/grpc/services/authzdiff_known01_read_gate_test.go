package services

// authzdiff_known01_read_gate_test.go -- regression coverage for the authzdiff
// cross-layer differential harness's known-01 waiver (PR #3981, a test-only
// harness not yet merged to main as of this fix -- its own
// server/authzdiff/REPORT.md is not in this tree; internal historical name
// D1): HTTP gates /groups, /users and /roles with an
// outer r.Use(RequirePermission(<read>)) on the whole route group PLUS a
// per-route RequirePermission(<write>) on the mutating ones, but the gRPC
// services only ever checked the specific write/assign permission. A principal
// holding ONLY the write permission (never granted the group's read permission)
// could mutate groups/users/roles over gRPC in cases REST would deny —
// authorizeGlobalMutation (conversions.go) closes that gap by requiring both,
// mirroring HTTP's layering exactly.
//
// Each case below proves the actual defect this closes: a principal holding
// ONLY the write/delete/assign permission (not the matching read permission)
// must be denied, and a principal holding both must succeed — for one
// representative mutating RPC per affected service, plus AddGroupMember
// (below). Red/green proof (CLAUDE.md "a security fix needs red/green proof"):
// checking out this branch's base commit (4fb37dcb, before this fix's first
// commit) and running these same write-only subtests fails every one with
// "must be denied" assertions seeing require.NoError pass instead (the bug: a
// users.write/roles.write-only holder was being let through); running them
// again at this fix's commit (or later) passes all of them. No production file
// was edited to produce the red state — it is the actual pre-fix history
// (TestGroupService_AddGroupMember_RequiresUsersRead is the one exception:
// AddGroupMember was fixed in a later commit on this same branch, after
// review flagged it, so its red state is this PR's own pre-fix commit, not
// main's history).
import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestGroupService_DeleteGroup_RequiresUsersRead: a principal holding ONLY
// users.write (the old, write-only gate) must be denied; a principal holding
// users.write + users.read (the new gate, matching HTTP's outer
// RequirePermission(users.read) on the /groups route group) must succeed.
func TestGroupService_DeleteGroup_RequiresUsersRead(t *testing.T) {
	svc, h := newGroupService(t)

	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "known01-group"})
	require.NoError(t, err)

	h.CreateTestUser(t, "writer-only", 2)
	writerRole := h.CreateTestRole(t, "known01-writer-only", "users.write only", 200)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'users.write'`, writerRole.ID)
	h.AssignUserRole(t, 2, writerRole.ID, nil)

	_, err = svc.DeleteGroup(authCtx(2, "writer-only"), &pb.DeleteGroupRequest{Id: g.GetId()})
	require.Error(t, err, "known-01: users.write holder without users.read must NOT be able to delete a group over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	h.CreateTestUser(t, "writer-reader", 3)
	fullRole := h.CreateTestRole(t, "known01-writer-reader", "users.write + users.read", 201)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name IN ('users.write', 'users.read')`, fullRole.ID)
	h.AssignUserRole(t, 3, fullRole.ID, nil)

	_, err = svc.DeleteGroup(authCtx(3, "writer-reader"), &pb.DeleteGroupRequest{Id: g.GetId()})
	require.NoError(t, err, "a holder of both users.write and users.read must still be able to delete a group")
}

// TestUserService_UpdateUser_RequiresUsersRead mirrors the group case for
// UserService.UpdateUser: users.write alone must be denied; users.write +
// users.read must succeed.
func TestUserService_UpdateUser_RequiresUsersRead(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	svc := NewUserService(h.CoreService)

	// Fixture users at explicit high IDs, created BEFORE the auto-assigned
	// "known01-target" below, so the two id spaces can't collide.
	//
	// Both fixture roles below hold system.read, matching the one extra
	// permission the default-assigned system_viewer role gives "known01-target"
	// (every new user gets it whether or not one is requested): without it,
	// RequireEqualOrGreaterAdminAuthority's permission-derived ceiling (a
	// separate, legitimate check UpdateUser already made before this fix, and
	// unrelated to known-01) would deny BOTH roles for a reason that has
	// nothing to do with known-01, masking the one gate this test exists to
	// isolate — users.read.
	h.CreateTestUser(t, "writer-only", 2)
	writerRole := h.CreateTestRole(t, "known01u-writer-only", "users.write + system.read, no users.read", 210)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name IN ('users.write', 'system.read')`, writerRole.ID)
	h.AssignUserRole(t, 2, writerRole.ID, nil)

	h.CreateTestUser(t, "writer-reader", 3)
	fullRole := h.CreateTestRole(t, "known01u-writer-reader", "users.write + users.read + system.read", 211)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name IN ('users.write', 'users.read', 'system.read')`, fullRole.ID)
	h.AssignUserRole(t, 3, fullRole.ID, nil)

	// Created last, after every explicit-ID fixture above, so its auto-assigned
	// ID can't collide with them.
	target := svc.mustCreate(t, "known01-target", "known01-target@example.com")

	_, err := svc.UpdateUser(authCtx(2, "writer-only"), &pb.UpdateUserRequest{
		Id: target.GetId(), DisplayName: strPtr("renamed"),
	})
	require.Error(t, err, "known-01: users.write holder without users.read must NOT be able to update a user over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = svc.UpdateUser(authCtx(3, "writer-reader"), &pb.UpdateUserRequest{
		Id: target.GetId(), DisplayName: strPtr("renamed-ok"),
	})
	require.NoError(t, err, "a holder of both users.write and users.read must still be able to update a user")
}

// TestRoleService_DeleteRole_RequiresRolesRead mirrors the group case for
// RoleService.DeleteRole: roles.write alone must be denied; roles.write +
// roles.read must succeed.
func TestRoleService_DeleteRole_RequiresRolesRead(t *testing.T) {
	svc, h := newRoleService(t)
	target := h.CreateTestRole(t, "known01-target-role", "unused role to delete", 220)

	h.CreateTestUser(t, "writer-only", 2)
	writerRole := h.CreateTestRole(t, "known01r-writer-only", "roles.write only", 221)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.write'`, writerRole.ID)
	h.AssignUserRole(t, 2, writerRole.ID, nil)

	_, err := svc.DeleteRole(authCtx(2, "writer-only"), &pb.DeleteRoleRequest{Id: uint32(target.ID)})
	require.Error(t, err, "known-01: roles.write holder without roles.read must NOT be able to delete a role over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	h.CreateTestUser(t, "writer-reader", 3)
	fullRole := h.CreateTestRole(t, "known01r-writer-reader", "roles.write + roles.read", 222)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name IN ('roles.write', 'roles.read')`, fullRole.ID)
	h.AssignUserRole(t, 3, fullRole.ID, nil)

	_, err = svc.DeleteRole(authCtx(3, "writer-reader"), &pb.DeleteRoleRequest{Id: uint32(target.ID)})
	require.NoError(t, err, "a holder of both roles.write and roles.read must still be able to delete a role")
}

// TestGroupService_AddGroupMember_RequiresUsersRead: a principal holding ONLY
// roles.assign (the gate AddGroupMember kept even after the rest of this PR's
// fix, on the mistaken premise that the harness's generated-permission sweep
// didn't flag this RPC) must be denied; a principal holding roles.assign +
// users.read (matching HTTP's outer RequirePermission(users.read) on the
// /groups route group, exactly like CreateGroup/UpdateGroup/DeleteGroup/
// RestoreGroup/RemoveGroupMember above) must succeed. The target group here
// confers no role, so core.AddUserToGroup's validateGroupJoinRoles ceiling
// loop has nothing to check -- this test isolates the RPC's own outer gate,
// not the separate machine-granter ceiling already covered by
// group_service_machine_ceiling_test.go.
func TestGroupService_AddGroupMember_RequiresUsersRead(t *testing.T) {
	svc, h := newGroupService(t)

	g, err := svc.CreateGroup(groupCtx(), &pb.CreateGroupRequest{Name: "known01-addmember-group"})
	require.NoError(t, err)
	target := h.CreateTestUser(t, "known01-addmember-target", 60)

	h.CreateTestUser(t, "writer-only", 2)
	assignOnlyRoleNoUsersRead := h.CreateTestRole(t, "known01am-assign-only", "roles.assign only", 230)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.assign'`, assignOnlyRoleNoUsersRead.ID)
	h.AssignUserRole(t, 2, assignOnlyRoleNoUsersRead.ID, nil)

	_, err = svc.AddGroupMember(authCtx(2, "writer-only"), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(target.ID)})
	require.Error(t, err, "known-01: roles.assign holder without users.read must NOT be able to add a group member over gRPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	h.CreateTestUser(t, "writer-reader", 3)
	fullRole := h.CreateTestRole(t, "known01am-assign-reader", "roles.assign + users.read", 231)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name IN ('roles.assign', 'users.read')`, fullRole.ID)
	h.AssignUserRole(t, 3, fullRole.ID, nil)

	_, err = svc.AddGroupMember(authCtx(3, "writer-reader"), &pb.GroupMemberRequest{GroupId: g.GetId(), UserId: uint32(target.ID)})
	require.NoError(t, err, "a holder of both roles.assign and users.read must still be able to add a group member")
}
