package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gorm.io/gorm"

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

// TestRoleService_UpdateRole_ConcurrentNarrowingIsKept is REVIEW-3585-DEEP-1 F4
// over gRPC: a description-only UpdateRole must not send back the scope it read
// before core's transaction. Admin B's any -> project narrowing commits right
// after that read (the callback below) and must survive admin A's update.
func TestRoleService_UpdateRole_ConcurrentNarrowingIsKept(t *testing.T) {
	svc, h := newRoleService(t)
	ctx := context.Background()
	role, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{Name: "ops-all", Description: "ops", Permissions: []string{somePermission(t, h)}, AssignableScope: "any"})
	require.NoError(t, err)
	id := uint(role.GetId())

	armed := true
	require.NoError(t, h.DB.Callback().Query().After("gorm:query").Register("test:narrow-after-rpc-read", func(tx *gorm.DB) {
		if _, inTx := tx.Statement.ConnPool.(*sql.Tx); inTx || !armed {
			return
		}
		if r, ok := tx.Statement.Dest.(*models.Role); ok && r.ID == id {
			armed = false // admin B's narrowing commits between A's read and A's transaction
			require.NoError(t, h.DB.Model(&models.Role{}).Where("id = ?", id).Update("assignable_scope", models.RoleAssignableProject).Error)
		}
	}))

	_, err = svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: role.GetId(), Description: strPtr("renamed by A")})
	require.NoError(t, err)
	require.False(t, armed, "the concurrent narrowing never landed in the RPC's read window")
	stored, err := h.CoreService.Storage().GetRole(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, models.RoleAssignableProject, stored.AssignableScope, "A's description-only update undid B's narrowing")
	assert.Equal(t, "renamed by A", stored.Description)
}
