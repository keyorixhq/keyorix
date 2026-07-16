package services

// coverage_s17b_test.go — second sweep of coverage gaps NOT addressed by
// coverage_s17_test.go. Targets:
//
//   role_service.go:91     GetRole              (66.7%)
//   role_service.go:157    DeleteRole           (68.8%)
//   role_service.go:254    RemoveRole           (63.6%)
//   role_service.go:274    GetUserRoles         (75.0%)
//   group_service.go:52    GetGroup             (66.7%)
//   group_service.go:115   RestoreGroup         (63.6%)
//   group_service.go:133   GetGroupMembers      (75.0%)
//   user_service.go:143    UpdateUser           (63.6%)
//   audit_service.go:212   WriteAuditCheckpoint (50.0%)  -- error path
//   project_service.go:85  GetProjectRotationOrder (63.6%)
//   project_service.go:105 GetProjectRotationPlan  (72.7%)
//   project_service.go:141 UpdateProject           (76.5%)
//   connect_service.go:132 DeleteRefGrant       (66.7%)
//   dynamic_service.go     ClassifyConfig / IssueLease / RenewLease / RevokeAllLeases (63-64%)

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/connect"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ---------------------------------------------------------------------------
// GetRole — error paths
// ---------------------------------------------------------------------------

func TestGetRole_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.GetRole(context.Background(), &pb.GetRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetRole_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetRole(ctx, &pb.GetRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetRole_NotFound(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.GetRole(roleAdminCtx(), &pb.GetRoleRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteRole — additional error paths
// ---------------------------------------------------------------------------

func TestDeleteRole_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.DeleteRole(context.Background(), &pb.DeleteRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteRole_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteRole(ctx, &pb.DeleteRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDeleteRole_ZeroID(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteRole_NotFound(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// RemoveRole — error paths
// ---------------------------------------------------------------------------

func TestRemoveRole_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.RemoveRole(context.Background(), &pb.RemoveRoleRequest{UserId: 1, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRemoveRole_MissingFields(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: 0, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRemoveRole_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RemoveRole(ctx, &pb.RemoveRoleRequest{UserId: 1, RoleId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetUserRoles — error paths
// ---------------------------------------------------------------------------

func TestGetUserRoles_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.GetUserRoles(context.Background(), &pb.GetUserRolesRequest{UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetUserRoles_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetUserRoles(ctx, &pb.GetUserRolesRequest{UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetUserRoles_ZeroUserID(t *testing.T) {
	svc, _ := newRoleService(t)
	// user 0 → GetUserRoleAssignment should fail with "not found"
	_, err := svc.GetUserRoles(roleAdminCtx(), &pb.GetUserRolesRequest{UserId: 0})
	require.Error(t, err)
	// storage returns not-found or internal for user 0; both are acceptable
	code := status.Code(err)
	assert.True(t, code == codes.NotFound || code == codes.Internal,
		"expected NotFound or Internal, got %v", code)
}

// ---------------------------------------------------------------------------
// GetGroup / GetGroupMembers / RestoreGroup — error paths
// ---------------------------------------------------------------------------

func TestGetGroup_Unauthenticated(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.GetGroup(context.Background(), &pb.GetGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetGroup_PermissionDenied(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetGroup(ctx, &pb.GetGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetGroup_NotFound(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.GetGroup(groupCtx(), &pb.GetGroupRequest{Id: 99999})
	require.Error(t, err)
	// groupError wraps i18n key → Internal (key doesn't contain "not found" substring)
	code := status.Code(err)
	assert.True(t, code == codes.NotFound || code == codes.Internal,
		"expected NotFound or Internal, got %v", code)
}

func TestGetGroupMembers_Unauthenticated(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.GetGroupMembers(context.Background(), &pb.GetGroupMembersRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetGroupMembers_PermissionDenied(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetGroupMembers(ctx, &pb.GetGroupMembersRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRestoreGroup_Unauthenticated(t *testing.T) {
	svc, _ := newGroupService(t)
	_, err := svc.RestoreGroup(context.Background(), &pb.RestoreGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRestoreGroup_PermissionDenied(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RestoreGroup(ctx, &pb.RestoreGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRestoreGroup_ErrorPath(t *testing.T) {
	svc, _ := newGroupService(t)
	// Try to restore a group that has never been deleted (or doesn't exist at all).
	// core should return an error that maps to Internal via groupError.
	_, err := svc.RestoreGroup(groupCtx(), &pb.RestoreGroupRequest{Id: 99999})
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// UpdateUser — additional error paths
// ---------------------------------------------------------------------------

func TestUpdateUser_Unauthenticated(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.UpdateUser(context.Background(), &pb.UpdateUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateUser_PermissionDenied(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.UpdateUser(ctx, &pb.UpdateUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUpdateUser_ZeroID(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateUser_NotFound(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: 99999, Username: strPtr("ghost")})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// GetProjectRotationOrder / GetProjectRotationPlan — error paths
// ---------------------------------------------------------------------------

func TestGetProjectRotationOrder_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.GetProjectRotationOrder(context.Background(), &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetProjectRotationOrder_PermissionDenied(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetProjectRotationOrder(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetProjectRotationOrder_ZeroID(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProjectRotationOrder(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetProjectRotationOrder_ProjectNotFound(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	// Non-existent project: the scoped auth will fail with PermissionDenied (no scope).
	_, err := svc.GetProjectRotationOrder(ctx, &pb.GetProjectRequest{Id: 99999})
	require.Error(t, err)
	// scoped auth for an unknown project → PermissionDenied
	code := status.Code(err)
	assert.True(t, code == codes.PermissionDenied || code == codes.NotFound || code == codes.Internal,
		"expected PermissionDenied, NotFound, or Internal; got %v", code)
}

func TestGetProjectRotationPlan_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.GetProjectRotationPlan(context.Background(), &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestGetProjectRotationPlan_PermissionDenied(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.GetProjectRotationPlan(ctx, &pb.GetProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGetProjectRotationPlan_ZeroID(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProjectRotationPlan(ctx, &pb.GetProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetProjectRotationPlan_ProjectNotFound(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.GetProjectRotationPlan(ctx, &pb.GetProjectRequest{Id: 99999})
	require.Error(t, err)
	code := status.Code(err)
	assert.True(t, code == codes.PermissionDenied || code == codes.NotFound || code == codes.Internal,
		"expected PermissionDenied, NotFound, or Internal; got %v", code)
}

// ---------------------------------------------------------------------------
// UpdateProject — error paths
// ---------------------------------------------------------------------------

func TestUpdateProject_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.UpdateProject(context.Background(), &pb.UpdateProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateProject_ZeroID(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateProject_NotFound(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	name := "ghost"
	_, err := svc.UpdateProject(ctx, &pb.UpdateProjectRequest{Id: 99999, Name: name})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// WriteAuditCheckpoint — the "refusing to checkpoint" error path
// ---------------------------------------------------------------------------

func TestWriteAuditCheckpoint_ChainVerifyError(t *testing.T) {
	// The base rig has no encryption configured, so WriteAuditCheckpoint returns
	// "written=false" which maps to FailedPrecondition — same code but via the
	// !written branch, which is distinct from the auth-denied path already tested
	// in coverage_s17_test.go. Running it with system.write confirms both sub-paths
	// (err != nil and written==false) land on FailedPrecondition.
	svc := newAuditService(t)
	ctx := authCtx(1, "admin", "system.write")
	_, err := svc.WriteAuditCheckpoint(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// Connect DeleteRefGrant — error paths
// ---------------------------------------------------------------------------

func newConnectServiceFull(t *testing.T) *ConnectGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil) // super_admin → holds connect.read + roles.read + roles.write
	h.CoreService.SetConnectManager(connect.NewManager(nil))
	return NewConnectService(h.CoreService)
}

func connAdminCtx() context.Context {
	return authCtx(1, "admin", "connect.read", "roles.read", "roles.write")
}

func TestDeleteRefGrant_Unauthenticated(t *testing.T) {
	svc := newConnectServiceFull(t)
	_, err := svc.DeleteRefGrant(context.Background(), &pb.DeleteConnectRefGrantRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteRefGrant_PermissionDenied(t *testing.T) {
	svc := newConnectServiceFull(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteRefGrant(ctx, &pb.DeleteConnectRefGrantRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDeleteRefGrant_Idempotent(t *testing.T) {
	svc := newConnectServiceFull(t)
	// DeleteConnectRefGrant is idempotent: deleting a non-existent grant returns nil.
	_, err := svc.DeleteRefGrant(connAdminCtx(), &pb.DeleteConnectRefGrantRequest{Id: 99999})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Dynamic secret service — ClassifyConfig / IssueLease / RenewLease / RevokeAllLeases
// error paths (unauthenticated / zero-id / permission denied)
// ---------------------------------------------------------------------------

func TestClassifyConfig_Unauthenticated(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.ClassifyConfig(context.Background(), &pb.ClassifyDynamicConfigRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestClassifyConfig_ZeroID(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.ClassifyConfig(ctx, &pb.ClassifyDynamicConfigRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestClassifyConfig_NotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.ClassifyConfig(ctx, &pb.ClassifyDynamicConfigRequest{Id: 99999, Classification: "restricted"})
	require.Error(t, err)
	// loadConfigScoped returns NotFound when the config doesn't exist
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestIssueLease_Unauthenticated(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.IssueLease(context.Background(), &pb.IssueLeaseRequest{ConfigId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestIssueLease_ZeroConfigID(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.IssueLease(ctx, &pb.IssueLeaseRequest{ConfigId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestIssueLease_NotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.IssueLease(ctx, &pb.IssueLeaseRequest{ConfigId: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestRenewLease_Unauthenticated(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.RenewLease(context.Background(), &pb.RenewLeaseRequest{LeaseId: "some-id"})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRenewLease_EmptyLeaseID(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RenewLease(ctx, &pb.RenewLeaseRequest{LeaseId: ""})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRenewLease_NotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RenewLease(ctx, &pb.RenewLeaseRequest{LeaseId: "nonexistent-lease-id"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestRevokeAllLeases_Unauthenticated(t *testing.T) {
	svc := newDynamicTestRig(t)
	_, err := svc.RevokeAllLeases(context.Background(), &pb.RevokeAllLeasesRequest{ConfigId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeAllLeases_ZeroConfigID(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RevokeAllLeases(ctx, &pb.RevokeAllLeasesRequest{ConfigId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRevokeAllLeases_NotFound(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.RevokeAllLeases(ctx, &pb.RevokeAllLeasesRequest{ConfigId: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// ListGroups / ListRoles / ListProjects — permission-denied paths
// (improve coverage of the authorize path in these lower-coverage functions)
// ---------------------------------------------------------------------------

func TestListGroups_PermissionDenied(t *testing.T) {
	svc, _ := newGroupService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListGroups(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListRoles_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListRoles(ctx, &pb.ListRolesRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListProjects_PermissionDenied(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListProjects(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListEnvironments_PermissionDenied(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.ListEnvironments(ctx, &pb.ListEnvironmentsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestListEnvironments_ZeroProjectID(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.ListEnvironments(ctx, &pb.ListEnvironmentsRequest{ProjectId: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestListEnvironments_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.ListEnvironments(context.Background(), &pb.ListEnvironmentsRequest{ProjectId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
