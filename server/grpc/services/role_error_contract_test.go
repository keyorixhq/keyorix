package services

// REVFIX-3790-2: GetUserRoles reaches mapRoleError with core's wrap of
// storage.ErrUserNotFound (GetUserRoleAssignment). The old text match answered
// NotFound; the typed mapper must too. Driven through real core, like
// project_error_contract_test.go, so the test sees what core really returns.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestRoleService_GetUserRoles_MissingUser_NotFound(t *testing.T) {
	svc, _ := newRoleService(t)

	_, err := svc.GetUserRoles(roleAdminCtx(), &pb.GetUserRolesRequest{UserId: 999999})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
	assert.Equal(t, "user not found", status.Convert(err).Message())
}

// REVFIX-3790-5 (REVIEW-3790-DEEP-5 F1): CreateRole with a permission listed
// twice reaches mapRoleError with storage.ErrDuplicateRolePermission (the second
// AssignPermissionToRole hits role_permissions' primary key). main's substring
// match answered AlreadyExists; the typed mapper must too, not Internal.
func TestRoleService_CreateRole_RepeatedPermission_AlreadyExists(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)

	_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
		Name: "repeated-perm-role", Description: "d", Permissions: []string{perm, perm},
	})
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "%v", err)
	assert.Equal(t, "the role already has that permission", status.Convert(err).Message())
}
