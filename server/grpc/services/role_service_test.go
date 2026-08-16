package services

import (
	"context"
	"strings"
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

// TestRoleService_CreateRole_NameTooShort mirrors HTTP's CreateRoleRequest.Name
// `min=3` bound (server/http/handlers/rbac.go) — gRPC must reject the same
// input HTTP would (#191).
func TestRoleService_CreateRole_NameTooShort(t *testing.T) {
	svc, h := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "ab", Description: "a valid description", Permissions: []string{somePermission(t, h)},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRoleService_CreateRole_NameTooLong mirrors HTTP's `max=50` bound (#191).
func TestRoleService_CreateRole_NameTooLong(t *testing.T) {
	svc, h := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: strings.Repeat("a", 51), Description: "a valid description", Permissions: []string{somePermission(t, h)},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestRoleService_CreateRole_DescriptionTooLong mirrors HTTP's
// `max=200` bound on Description (#191).
func TestRoleService_CreateRole_DescriptionTooLong(t *testing.T) {
	svc, h := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "valid-role-name", Description: strings.Repeat("d", 201), Permissions: []string{somePermission(t, h)},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRoleService_UpdateRole_DescriptionTooLong(t *testing.T) {
	svc, h := newRoleService(t)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "u-role-len", Description: "old", Permissions: []string{somePermission(t, h)},
	})
	require.NoError(t, err)

	_, err = svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Description: strPtr(strings.Repeat("d", 201)),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRoleService_CreateRole_UnknownPermission(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "unknown-perm-role", Description: "y", Permissions: []string{"does.not.exist"},
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

// TestRoleService_UpdateRole_BuiltinRefused proves the gRPC path refuses to
// update a product built-in role, matching the HTTP handler. Without the guard a
// roles.write holder could shrink super_admin/admin's permission set over gRPC
// (UpdateRole strips the entire current set before re-adding the caller-supplied
// one) and lock out every administrator who relies on that role. A non-built-in
// role must remain updatable, matching TestRoleService_UpdateRole above.
func TestRoleService_UpdateRole_BuiltinRefused(t *testing.T) {
	svc, _ := newRoleService(t)
	// super_admin is seeded with ID 1 by the RBAC test helper.
	_, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: 1, Description: strPtr("hijacked description"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// And it is unchanged afterwards.
	got, gerr := svc.GetRole(roleAdminCtx(), &pb.GetRoleRequest{Id: 1})
	require.NoError(t, gerr)
	assert.Equal(t, "super_admin", got.GetName())
	assert.NotEqual(t, "hijacked description", got.GetDescription())
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

// TestRoleService_DeleteRole_BuiltinRefused proves the gRPC path refuses to
// delete a product built-in role, matching the HTTP handler. Without the guard a
// roles.write holder could delete super_admin/admin over gRPC and lock out admins.
func TestRoleService_DeleteRole_BuiltinRefused(t *testing.T) {
	svc, _ := newRoleService(t)
	// super_admin is seeded with ID 1 by the RBAC test helper.
	_, err := svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	// And it is still present afterwards.
	got, gerr := svc.GetRole(roleAdminCtx(), &pb.GetRoleRequest{Id: 1})
	require.NoError(t, gerr)
	assert.Equal(t, "super_admin", got.GetName())
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

// TestRoleService_GetUserRoles_RequiresRolesAssign is the G16 regression test:
// GetUserRoles calls the identical core.GetUserRoleAssignment the HTTP sibling
// RBACHandler.GetUserRoles does (server/http/router.go: GET /roles/user/{userId}),
// which is deliberately gated behind roles.assign, not the weaker roles.read
// that gates the rest of the /roles group — disclosing an arbitrary user's full
// role assignment is reconnaissance for a privilege-escalation attempt. A
// roles.read-only holder (e.g. the seeded auditor role) must be refused; a
// roles.assign holder must succeed.
func TestRoleService_GetUserRoles_RequiresRolesAssign(t *testing.T) {
	svc, h := newRoleService(t)
	target := h.CreateTestUser(t, "target", 501)

	// User 2 holds ONLY roles.read (the old, too-weak gate) — must be refused.
	h.CreateTestUser(t, "reader-only", 2)
	readerRole := h.CreateTestRole(t, "roles_read_only", "roles.read only", 200)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.read'`, readerRole.ID)
	h.AssignUserRole(t, 2, readerRole.ID, nil)

	_, err := svc.GetUserRoles(authCtx(2, "reader-only"), &pb.GetUserRolesRequest{UserId: intToU32(int(target.ID))})
	require.Error(t, err, "roles.read holder without roles.assign must NOT call GetUserRoles")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// User 3 holds roles.assign (the new, correct gate) — must succeed.
	h.CreateTestUser(t, "assigner-only", 3)
	assignerRole := h.CreateTestRole(t, "roles_assign_only", "roles.assign only", 201)
	h.ExecuteRawSQL(t, `INSERT INTO role_permissions (role_id, permission_id)
		SELECT ?, id FROM permissions WHERE name = 'roles.assign'`, assignerRole.ID)
	h.AssignUserRole(t, 3, assignerRole.ID, nil)

	got, err := svc.GetUserRoles(authCtx(3, "assigner-only"), &pb.GetUserRolesRequest{UserId: intToU32(int(target.ID))})
	require.NoError(t, err, "roles.assign holder should be allowed to call GetUserRoles")
	assert.Equal(t, "target", got.GetUsername())
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

// #169: the gRPC path closes the same escalation as HTTP — an actor holding ONLY
// roles.write (no system.write, no admin role) must not be able to bundle
// system.write into a role's definition, whether creating a new role or updating an
// existing one they already hold.
func TestRoleService_CreateRole_RolesWriteHolderCannotBundleSystemWrite(t *testing.T) {
	svc, h := newRoleService(t)
	roleEditor := h.CreateTestRole(t, "role-editor", "can edit roles only", 100)
	require.NoError(t, h.DB.Exec(
		"INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = 'roles.write'",
		roleEditor.ID).Error)
	h.CreateTestUser(t, "attacker", 700)
	h.AssignUserRole(t, 700, roleEditor.ID, nil)

	ctx := authCtx(700, "attacker")
	_, err := svc.CreateRole(ctx, &pb.CreateRoleRequest{
		Name: "self-promote", Description: "escalation attempt", Permissions: []string{"system.write"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	var roleCount int64
	require.NoError(t, h.DB.Model(&models.Role{}).Where("name = ?", "self-promote").Count(&roleCount).Error)
	assert.Zero(t, roleCount, "no role must be created when a bundled permission is refused")
}

func TestRoleService_UpdateRole_RolesWriteHolderCannotAddSystemWrite(t *testing.T) {
	svc, h := newRoleService(t)
	roleEditor := h.CreateTestRole(t, "role-editor", "can edit roles only", 100)
	require.NoError(t, h.DB.Exec(
		"INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = 'roles.write'",
		roleEditor.ID).Error)
	target := h.CreateTestRole(t, "target", "a role the attacker already holds", 101)
	require.NoError(t, h.DB.Exec(
		"INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = 'roles.write'",
		target.ID).Error)
	h.CreateTestUser(t, "attacker2", 701)
	h.AssignUserRole(t, 701, roleEditor.ID, nil)
	h.AssignUserRole(t, 701, target.ID, nil)

	ctx := authCtx(701, "attacker2")
	_, err := svc.UpdateRole(ctx, &pb.UpdateRoleRequest{
		Id: uint32(target.ID), Permissions: []string{"roles.write", "system.write"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	var permCount int64
	require.NoError(t, h.DB.Table("role_permissions").Where("role_id = ?", target.ID).Count(&permCount).Error)
	assert.Equal(t, int64(1), permCount, "the role's permission set must be unchanged")
}

// #294: closes the same reserved-name admin-bypass gap as the HTTP handler test
// (rbac_role_escalation_test.go's TestCreateRole_CannotClaimReservedAdminBypassName)
// over gRPC, which has its own independent CreateRole path.
func TestRoleService_CreateRole_CannotClaimReservedAdminBypassName(t *testing.T) {
	svc, h := newRoleService(t)
	roleEditor := h.CreateTestRole(t, "role-editor-2", "can edit roles only", 102)
	require.NoError(t, h.DB.Exec(
		"INSERT INTO role_permissions (role_id, permission_id) SELECT ?, id FROM permissions WHERE name = 'roles.write'",
		roleEditor.ID).Error)
	h.CreateTestUser(t, "attacker3", 702)
	h.AssignUserRole(t, 702, roleEditor.ID, nil)

	ctx := authCtx(702, "attacker3")
	// RBACTestHelper.SeedDefaultRolesAndPermissions pre-seeds "super_admin"/"admin"/
	// "editor"/"viewer"/"auditor"/"system_viewer" as realistic fixture roles — a fresh
	// create attempt for any of THOSE names would collide with the unique(name)
	// constraint regardless of this fix, so AlreadyExists alone doesn't prove the
	// reserved-name guard fired for them. "system_admin" and "project_admin" are NOT
	// pre-seeded by this harness, so their rejection can only come from the guard.
	for _, reserved := range []string{"super_admin", "auditor", "admin", "system_admin", "project_admin"} {
		_, err := svc.CreateRole(ctx, &pb.CreateRoleRequest{
			Name: reserved, Description: "reserved-name attempt", Permissions: []string{"roles.write"},
		})
		require.Error(t, err, "creating a role named %q must be refused", reserved)
		assert.Equal(t, codes.AlreadyExists, status.Code(err))
	}

	var count int64
	require.NoError(t, h.DB.Model(&models.Role{}).Where("name = ?", "system_admin").Count(&count).Error)
	assert.Zero(t, count, "no role named system_admin must exist — this name isn't pre-seeded, so its rejection proves the guard fired")
	require.NoError(t, h.DB.Model(&models.Role{}).Where("name = ?", "project_admin").Count(&count).Error)
	assert.Zero(t, count, "no role named project_admin must exist — this name isn't pre-seeded, so its rejection proves the guard fired")
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
