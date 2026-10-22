package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// GROUP-ROLE-SCOPE-1 Phase 2 (#3546), gRPC side of
// server/http/role_assignable_scope_http_test.go: the role's assignable scope
// is set on create, changed on update, returned on every Role, and an invalid
// value is InvalidArgument. Asserts the stored row, not only the response.
func TestRoleService_AssignableScope(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)
	ctx := context.Background()
	stored := func(id uint32) string {
		r, err := h.CoreService.Storage().GetRole(ctx, uint(id))
		require.NoError(t, err)
		return r.AssignableScope
	}

	role, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{Name: "deployers", Description: "ci", Permissions: []string{perm}})
	require.NoError(t, err)
	assert.Equal(t, models.RoleAssignableProject, role.GetAssignableScope(), "a new role defaults to project")
	assert.Equal(t, models.RoleAssignableProject, stored(role.GetId()))

	widened, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{Name: "ops-all", Description: "ops", Permissions: []string{perm}, AssignableScope: "any"})
	require.NoError(t, err)
	assert.Equal(t, models.RoleAssignableAny, stored(widened.GetId()))

	_, err = svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{Name: "bad-scope", Description: "x", Permissions: []string{perm}, AssignableScope: "everywhere"})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)

	scope := "global"
	updated, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: role.GetId(), AssignableScope: &scope})
	require.NoError(t, err)
	assert.Equal(t, models.RoleAssignableGlobal, updated.GetAssignableScope())
	assert.Equal(t, models.RoleAssignableGlobal, stored(role.GetId()))

	bogus := "bogus"
	_, err = svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: role.GetId(), AssignableScope: &bogus})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "%v", err)
	assert.Equal(t, models.RoleAssignableGlobal, stored(role.GetId()), "a refused update changes nothing")
}
