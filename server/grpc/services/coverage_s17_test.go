package services

// coverage_s17_test.go — targeted tests to increase coverage on the functions
// listed in the round-17 coverage gap report:
//
//   group_service.go:201     groupError          (37.5%)
//   audit_service.go:212     WriteAuditCheckpoint (38.9%)
//   user_service.go:290      mapUserError        (42.9%)
//   machine_identity_service.go:143 IssueMachineToken (60%)
//   machine_identity_service.go:194 RevokeMachineToken (60%)
//   project_service.go:170   DeleteProject       (60%)
//   user_service.go:168      DeleteUser          (60%)
//   break_glass_service.go:69 RevokeBreakGlass   (62.5%)
//   group_service.go:101     DeleteGroup         (62.5%)
//   group_service.go:152     AddGroupMember      (62.5%)
//   group_service.go:166     RemoveGroupMember   (62.5%)
//   role_service.go:103      UpdateRole          (62.1%)

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ---------------------------------------------------------------------------
// groupError — error-mapping helper
// ---------------------------------------------------------------------------

func TestGroupError_NotFound(t *testing.T) {
	err := groupError(errors.New("group not found"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGroupError_AlreadyExists(t *testing.T) {
	err := groupError(errors.New("group already exists"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestGroupError_Duplicate(t *testing.T) {
	err := groupError(errors.New("duplicate group entry"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestGroupError_InUse(t *testing.T) {
	err := groupError(errors.New("name is in use by another group"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestGroupError_Required(t *testing.T) {
	err := groupError(errors.New("name is required"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGroupError_Invalid(t *testing.T) {
	err := groupError(errors.New("invalid group name"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGroupError_Exceeds(t *testing.T) {
	err := groupError(errors.New("name exceeds maximum length"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGroupError_Permission(t *testing.T) {
	err := groupError(errors.New("permission denied"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGroupError_Denied(t *testing.T) {
	err := groupError(errors.New("access denied to group"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGroupError_AdministratorCanGrant(t *testing.T) {
	err := groupError(errors.New("only an administrator can grant membership"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestGroupError_RefusingToRemoveLast(t *testing.T) {
	err := groupError(errors.New("refusing to remove the last member"))
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestGroupError_Default(t *testing.T) {
	err := groupError(errors.New("unexpected backend failure"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// mapUserError — error-mapping helper
// ---------------------------------------------------------------------------

func TestMapUserError_NotFound(t *testing.T) {
	err := mapUserError(errors.New("user not found"))
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestMapUserError_AlreadyExists(t *testing.T) {
	err := mapUserError(errors.New("user already exists"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestMapUserError_Duplicate(t *testing.T) {
	err := mapUserError(errors.New("duplicate email in users"))
	assert.Equal(t, codes.AlreadyExists, status.Code(err))
}

func TestMapUserError_AdministratorCanGrant(t *testing.T) {
	err := mapUserError(errors.New("only an administrator can grant this role"))
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestMapUserError_Validation(t *testing.T) {
	err := mapUserError(errors.New("validation error: email format"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_Required(t *testing.T) {
	err := mapUserError(errors.New("username is required"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_Invalid(t *testing.T) {
	err := mapUserError(errors.New("invalid email address"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_MustBe(t *testing.T) {
	err := mapUserError(errors.New("password must be at least 8 characters"))
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestMapUserError_Default(t *testing.T) {
	err := mapUserError(errors.New("connection reset by peer"))
	assert.Equal(t, codes.Internal, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteGroup — error and success paths
// ---------------------------------------------------------------------------

// newGroupServiceFull builds the group service and also returns the helper so
// tests can inspect the DB or seed additional data.
func newGroupServiceFull(t *testing.T) (*GroupGRPCService, *testhelper.RBACTestHelper) {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin (global)
	return NewGroupService(h.CoreService), h
}

func TestDeleteGroup_NotFound(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	_, err := svc.DeleteGroup(groupCtx(), &pb.DeleteGroupRequest{Id: 99999})
	require.Error(t, err)
	// The i18n key "ErrorGroupNotFound" is returned verbatim (not in locale file),
	// which doesn't match "not found" in groupError → maps to Internal.
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestDeleteGroup_Unauthenticated(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	_, err := svc.DeleteGroup(context.Background(), &pb.DeleteGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteGroup_PermissionDenied(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	// authCtx with no users.write permission.
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteGroup(ctx, &pb.DeleteGroupRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// AddGroupMember / RemoveGroupMember — error paths
// ---------------------------------------------------------------------------

func TestAddGroupMember_NonExistentGroup(t *testing.T) {
	svc, h := newGroupServiceFull(t)
	// Create user 2 so the GetUser check in AddUserToGroup passes; group 99999
	// does not exist → GetGroup fails with the i18n key "ErrorGroupNotFound" which
	// wraps to "not found" indirectly via storage's wrapping error. The storage
	// layer calls GetUser first (succeeds) then GetGroup(99999) fails.
	h.CreateTestUser(t, "alice", 2)
	_, err := svc.AddGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: 99999, UserId: 2})
	require.Error(t, err)
	// groupError falls through to Internal because the i18n key returned verbatim
	// does not contain the "not found" substring (no space).
	assert.Equal(t, codes.Internal, status.Code(err))
}

func TestAddGroupMember_Unauthenticated(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	_, err := svc.AddGroupMember(context.Background(), &pb.GroupMemberRequest{GroupId: 1, UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAddGroupMember_PermissionDenied(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	ctx := authCtx(999, "nobody") // no roles.assign
	_, err := svc.AddGroupMember(ctx, &pb.GroupMemberRequest{GroupId: 1, UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRemoveGroupMember_NoErrorOnNonExistentMembership(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	// RemoveUserFromGroup in storage issues a DELETE with no rows matched — it
	// returns nil (idempotent remove), so a non-existent membership is not an error.
	_, err := svc.RemoveGroupMember(groupCtx(), &pb.GroupMemberRequest{GroupId: 99999, UserId: 1})
	require.NoError(t, err)
}

func TestRemoveGroupMember_Unauthenticated(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	_, err := svc.RemoveGroupMember(context.Background(), &pb.GroupMemberRequest{GroupId: 1, UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRemoveGroupMember_PermissionDenied(t *testing.T) {
	svc, _ := newGroupServiceFull(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RemoveGroupMember(ctx, &pb.GroupMemberRequest{GroupId: 1, UserId: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteUser — additional error paths
// ---------------------------------------------------------------------------

func TestDeleteUser_ZeroID(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteUser_Unauthenticated(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.DeleteUser(context.Background(), &pb.DeleteUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteUser_PermissionDenied(t *testing.T) {
	svc := newUserService(t)
	// No users.delete permission.
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteUser(ctx, &pb.DeleteUserRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDeleteUser_NotFound(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Id: 99999})
	require.Error(t, err)
	// mapUserError maps "not found" → NotFound.
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// DeleteProject — additional error paths
// ---------------------------------------------------------------------------

func TestDeleteProject_ZeroID(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestDeleteProject_Unauthenticated(t *testing.T) {
	svc := newProjectTestRig(t)
	_, err := svc.DeleteProject(context.Background(), &pb.DeleteProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestDeleteProject_PermissionDenied(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestDeleteProject_NotFound(t *testing.T) {
	svc := newProjectTestRig(t)
	ctx := authCtx(1, "owner")
	_, err := svc.DeleteProject(ctx, &pb.DeleteProjectRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// IssueMachineToken — additional paths
// ---------------------------------------------------------------------------

func TestIssueMachineToken_ZeroProjectID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 0, MachineId: 1, Name: "tok",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestIssueMachineToken_ZeroMachineID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: 0, Name: "tok",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestIssueMachineToken_Unauthenticated(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.IssueMachineToken(context.Background(), &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: 1, Name: "tok",
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestIssueMachineToken_PermissionDenied(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: 1, Name: "tok",
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestIssueMachineToken_NotFound(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: 99999, Name: "tok",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestIssueMachineToken_WithExpiry(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	// Create machine first.
	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "expiry-machine",
	})
	require.NoError(t, err)
	// Issue a token with a 7-day expiry.
	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "deploy", ExpiresInDays: 7,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, issued.GetToken())
	require.NotNil(t, issued.GetExpiresAt())
}

// ---------------------------------------------------------------------------
// RevokeMachineToken — additional paths
// ---------------------------------------------------------------------------

func TestRevokeMachineToken_ZeroTokenID(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 0,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRevokeMachineToken_Unauthenticated(t *testing.T) {
	svc := newMachineTestRig(t)
	_, err := svc.RevokeMachineToken(context.Background(), &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeMachineToken_PermissionDenied(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: 1, TokenId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRevokeMachineToken_NotFound(t *testing.T) {
	svc := newMachineTestRig(t)
	ctx := authCtx(1, "admin")
	_, err := svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: 99999, TokenId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// ---------------------------------------------------------------------------
// RevokeBreakGlass — additional paths
// ---------------------------------------------------------------------------

func newBreakGlassServiceFull(t *testing.T) *BreakGlassGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	require.NoError(t, h.DB.AutoMigrate(&models.BreakGlassActivation{}, &models.AuditEvent{}))
	h.AssignUserRole(t, 1, 1, nil) // user 1 = super_admin (global)
	proj := uint(1)
	h.AssignUserRole(t, 1, 4, &proj) // viewer at project 1
	h.CreateTestRole(t, "emergency", "break-glass role", 90)
	h.CoreService.SetBreakGlassPolicy(core.BreakGlassPolicy{
		Enabled: true, EmergencyRole: "emergency", DefaultTTL: time.Hour, MaxTTL: 4 * time.Hour,
	})
	return NewBreakGlassService(h.CoreService)
}

func TestRevokeBreakGlass_Unauthenticated(t *testing.T) {
	svc := newBreakGlassServiceFull(t)
	_, err := svc.RevokeBreakGlass(context.Background(), &pb.RevokeBreakGlassRequest{
		ProjectId: 1, ActivationId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestRevokeBreakGlass_PermissionDenied(t *testing.T) {
	svc := newBreakGlassServiceFull(t)
	ctx := authCtx(999, "nobody") // no roles.assign
	_, err := svc.RevokeBreakGlass(ctx, &pb.RevokeBreakGlassRequest{
		ProjectId: 1, ActivationId: 1,
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestRevokeBreakGlass_NotFound(t *testing.T) {
	svc := newBreakGlassServiceFull(t)
	_, err := svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{
		ProjectId: 1, ActivationId: 99999,
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestRevokeBreakGlass_AlreadyRevoked(t *testing.T) {
	svc := newBreakGlassServiceFull(t)

	act, err := svc.ActivateBreakGlass(bgCtx(), &pb.ActivateBreakGlassRequest{
		ProjectId: 1, Justification: "incident #1", Ttl: "1h",
	})
	require.NoError(t, err)

	// First revoke succeeds.
	_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{
		ProjectId: 1, ActivationId: act.GetId(),
	})
	require.NoError(t, err)

	// Second revoke on an already-revoked activation → FailedPrecondition.
	_, err = svc.RevokeBreakGlass(bgCtx(), &pb.RevokeBreakGlassRequest{
		ProjectId: 1, ActivationId: act.GetId(),
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

// ---------------------------------------------------------------------------
// UpdateRole — additional paths (beyond description-too-long, which is tested
// in role_service_test.go) to cover the permission-replacement branch and the
// error sub-paths.
// ---------------------------------------------------------------------------

func TestUpdateRole_Unauthenticated(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.UpdateRole(context.Background(), &pb.UpdateRoleRequest{Id: 1})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUpdateRole_ZeroID(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: 0})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateRole_PermissionDenied(t *testing.T) {
	svc, _ := newRoleService(t)
	ctx := authCtx(999, "nobody")
	_, err := svc.UpdateRole(ctx, &pb.UpdateRoleRequest{Id: 1, Description: strPtr("x")})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUpdateRole_NotFound(t *testing.T) {
	svc, _ := newRoleService(t)
	_, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: 99999, Description: strPtr("new")})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestUpdateRole_ReplacePermissions(t *testing.T) {
	svc, h := newRoleService(t)
	perms, err := h.CoreService.Storage().ListPermissions(context.Background())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(perms), 2, "need at least 2 permissions to test replacement")

	// Create a role with the first permission.
	p0 := perms[0].Name
	p1 := perms[1].Name
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "swap-perm-role", Description: "d", Permissions: []string{p0},
	})
	require.NoError(t, err)
	require.Len(t, created.GetPermissions(), 1)
	assert.Equal(t, p0, created.GetPermissions()[0].GetName())

	// Replace with the second permission.
	updated, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Permissions: []string{p1},
	})
	require.NoError(t, err)
	require.Len(t, updated.GetPermissions(), 1)
	assert.Equal(t, p1, updated.GetPermissions()[0].GetName())
}

func TestUpdateRole_UnknownPermission(t *testing.T) {
	svc, h := newRoleService(t)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "pre-update-role", Description: "d", Permissions: []string{somePermission(t, h)},
	})
	require.NoError(t, err)

	_, err = svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Permissions: []string{"does.not.exist"},
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUpdateRole_DescriptionAndPermissions(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)
	created, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "combo-role", Description: "original", Permissions: []string{perm},
	})
	require.NoError(t, err)

	// Update both description and permissions in one request.
	updated, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{
		Id: created.GetId(), Description: strPtr("updated"), Permissions: []string{perm},
	})
	require.NoError(t, err)
	assert.Equal(t, "updated", updated.GetDescription())
	require.Len(t, updated.GetPermissions(), 1)
}

// ---------------------------------------------------------------------------
// WriteAuditCheckpoint — permission-denied path (system.write required)
// ---------------------------------------------------------------------------

func TestWriteAuditCheckpoint_PermissionDenied(t *testing.T) {
	svc := newAuditService(t)
	ctx := authCtx(7, "nobody") // ungranted → denied on system.write
	_, err := svc.WriteAuditCheckpoint(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestWriteAuditCheckpoint_Unauthenticated(t *testing.T) {
	svc := newAuditService(t)
	_, err := svc.WriteAuditCheckpoint(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
