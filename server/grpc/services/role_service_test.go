package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func newRoleService(t *testing.T) (*RoleGRPCService, *testhelper.RBACTestHelper) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	// Admin-context user (id 1) = super_admin (global); denied tests use an
	// ungranted user id so core.Authorize refuses them.
	h.AssignUserRole(t, 1, 1, nil)
	return NewRoleService(h.CoreService), h
}

func roleAdminCtx() context.Context {
	return authCtx(1, "admin", "roles.read", "roles.write", "roles.assign")
}

// somePermission returns the name of a permission seeded by the RBAC helper.
func somePermission(t *testing.T, h *testhelper.RBACTestHelper) string {
	t.Helper()
	perms, err := h.CoreService.Storage().ListPermissions(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, perms)
	return perms[0].Name
}

func TestRoleService_CreateRole(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)

	role, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "custom-role", Description: "a custom role", Permissions: []string{perm},
	})
	require.NoError(t, err)
	assert.NotZero(t, role.GetId())
	assert.Equal(t, "custom-role", role.GetName())
	require.Len(t, role.GetPermissions(), 1)
	assert.Equal(t, perm, role.GetPermissions()[0].GetName())
}

func TestRoleService_CreateRole_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(context.Background(), &pb.CreateRoleRequest{
		Name: "x", Description: "y", Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRoleService_CreateRole_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(7, "reader") // ungranted user → denied
	_, err := svc.CreateRole(ctx, &pb.CreateRoleRequest{
		Name: "x", Description: "y", Permissions: []string{"secrets.read"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRoleService_CreateRole_MissingFields(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{Name: "x", Description: "y"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRoleService_CreateRole_UnknownPermission(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "x", Description: "y", Permissions: []string{"does.not.exist"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRoleService_GetRole(t *testing.T) {
	svc, h := newRoleService(t)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "g-role", Description: "d", Permissions: []string{somePermission(t, h)},
	})
	require.NoError(t, err)

	got, err := svc.GetRole(roleAdminCtx(), &pb.GetRoleRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, "g-role", got.GetName())
}

func TestRoleService_UpdateRole(t *testing.T) {
	svc, h := newRoleService(t)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "u-role", Description: "old", Permissions: []string{somePermission(t, h)},
	})
	require.NoError(t, err)

	updated, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Description: strPtr("new description"),
	})
	require.NoError(t, err)
	assert.Equal(t, "new description", updated.GetDescription())
}

func TestRoleService_DeleteRole(t *testing.T) {
	svc, h := newRoleService(t)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "d-role", Description: "d", Permissions: []string{somePermission(t, h)},
	})
	require.NoError(t, err)

	_, err = svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: created.GetId()})
	require.NoError(t, err)

	_, err = svc.GetRole(roleAdminCtx(), &pb.GetRoleRequest{Id: created.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// Role create/update/delete over gRPC must each leave an audit event, exactly as on
// HTTP — the underlying Storage() calls do not audit internally, so without the
// service firing LogRole* these lifecycle changes were invisible in the audit trail
// when driven over gRPC. The writes are synchronous, so assert directly.
func TestRoleService_LifecycleAuditedOverGRPC(t *testing.T) {
	svc, h := newRoleService(t)
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))
	perm := somePermission(t, h)

	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "lifecycle-role", Description: "d", Permissions: []string{perm},
	})
	require.NoError(t, err)
	_, err = svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Description: strPtr("new"),
	})
	require.NoError(t, err)
	_, err = svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: created.GetId()})
	require.NoError(t, err)

	count := func(evType string) int64 {
		var n int64
		require.NoError(t, h.DB.Model(&models.AuditEvent{}).
			Where("event_type = ? AND user_id = ?", evType, 1).Count(&n).Error)
		return n
	}
	assert.Equal(t, int64(1), count("role.created"), "CreateRole over gRPC must be audited")
	assert.Equal(t, int64(1), count("role.updated"), "UpdateRole over gRPC must be audited")
	assert.Equal(t, int64(1), count("role.deleted"), "DeleteRole over gRPC must be audited")
}

func TestRoleService_ListRoles(t *testing.T) {
	svc, _ := newRoleService(t)
	resp, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetRoles()), 1) // helper seeds standard roles
}

func TestRoleService_AssignAndGetUserRoles(t *testing.T) {
	svc, h := newRoleService(t)
	user := h.CreateTestUser(t, "assignee", 500)

	roles, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, roles.GetRoles())
	roleID := roles.GetRoles()[0].GetId()

	assignment, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{
		UserId: intToU32(int(user.ID)), RoleId: roleID,
	})
	require.NoError(t, err)
	assert.Equal(t, roleID, assignment.GetRoleId())

	got, err := svc.GetUserRoles(roleAdminCtx(), &pb.GetUserRolesRequest{UserId: intToU32(int(user.ID))})
	require.NoError(t, err)
	assert.Equal(t, "assignee", got.GetUsername())
	assert.GreaterOrEqual(t, len(got.GetRoles()), 1)
}

// Regression for the flat-vs-scoped gRPC bug: a caller holding admin/roles.assign
// ONLY at project 1 may assign within project 1 but NOT cross-project into project
// 2. Before the fix, AssignRole checked the flat global permission union, so a
// project-1 admin could grant roles into any project.
func TestRoleService_AssignRole_ScopedCrossProjectDenied(t *testing.T) {
	svc, h := newRoleService(t)
	proj1 := uint(1)
	h.AssignUserRole(t, 50, 2, &proj1) // user 50 = admin (role 2) at project 1 only
	target := h.CreateTestUser(t, "xtarget", 600)
	roles, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	roleID := roles.GetRoles()[0].GetId()
	ctx := authCtx(50, "projadmin") // perms slice is ignored — authz is scope-resolved
	p1, p2 := uint32(1), uint32(2)

	// Within the caller's project: allowed (project-scoped admin bypass).
	_, err = svc.AssignRole(ctx, &pb.AssignRoleRequest{
		UserId: intToU32(int(target.ID)), RoleId: roleID, ProjectId: &p1,
	})
	require.NoError(t, err)

	// Into a different project: denied — the grant doesn't apply there.
	_, err = svc.AssignRole(ctx, &pb.AssignRoleRequest{
		UserId: intToU32(int(target.ID)), RoleId: roleID, ProjectId: &p2,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRoleService_RemoveRole(t *testing.T) {
	svc, h := newRoleService(t)
	user := h.CreateTestUser(t, "removee", 501)
	roles, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	roleID := roles.GetRoles()[0].GetId()

	_, err = svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(user.ID)), RoleId: roleID})
	require.NoError(t, err)

	_, err = svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: intToU32(int(user.ID)), RoleId: roleID})
	require.NoError(t, err)
}
