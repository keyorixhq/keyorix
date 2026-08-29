// role_builtin_denial_audit_test.go — #1503: UpdateRole/DeleteRole refuse a
// built-in role (core.IsBuiltinRole) but, before this fix, wrote no audit
// event for the refusal — unlike every other RBAC/Connect deny path. These
// tests assert the audit event lands, not just that the request is refused
// (the FailedPrecondition itself was already covered by
// TestDeleteRole_BuiltinDenied_S21b in coverage_s21b_test.go).
package services

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// findBuiltinRoleID looks up super_admin's ID via the service's own ListRoles
// (mirrors TestDeleteRole_BuiltinDenied_S21b's own lookup approach) rather than
// assuming a fixed seeded ID.
func findBuiltinRoleID(t *testing.T, svc *RoleGRPCService) uint32 {
	t.Helper()
	roles, err := svc.ListRoles(roleAdminCtx(), &pb.ListRolesRequest{})
	require.NoError(t, err)
	for _, r := range roles.GetRoles() {
		if r.GetName() == "super_admin" {
			return r.GetId()
		}
	}
	t.Skip("super_admin role not found in test rig; skipping builtin-denial audit test")
	return 0
}

// TestUpdateRole_BuiltinDenied_AuditsTheDenial is the gRPC-transport half of
// #1503: attempting to update a built-in role must both refuse
// (FailedPrecondition, pre-existing behavior, unchanged) AND write a
// Success=false audit event naming the role -- previously it did neither.
func TestUpdateRole_BuiltinDenied_AuditsTheDenial(t *testing.T) {
	svc, h := newRoleService(t)
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))
	builtinID := findBuiltinRoleID(t, svc)

	_, err := svc.UpdateRole(roleAdminCtx(), &pb.UpdateRoleRequest{Id: builtinID})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	var event models.AuditEvent
	dberr := h.DB.Where("event_type = ? AND success = ?", core.EventRoleUpdated, false).First(&event).Error
	require.NoError(t, dberr, "the denied update must write a Success=false audit event")
	assert.Contains(t, event.Description, "super_admin", "the audit description must name the target role")
}

// TestDeleteRole_BuiltinDenied_AuditsTheDenial is the DeleteRole counterpart
// -- see TestUpdateRole_BuiltinDenied_AuditsTheDenial's doc comment.
func TestDeleteRole_BuiltinDenied_AuditsTheDenial(t *testing.T) {
	svc, h := newRoleService(t)
	require.NoError(t, h.DB.AutoMigrate(&models.AuditEvent{}))
	builtinID := findBuiltinRoleID(t, svc)

	_, err := svc.DeleteRole(roleAdminCtx(), &pb.DeleteRoleRequest{Id: builtinID})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	var event models.AuditEvent
	dberr := h.DB.Where("event_type = ? AND success = ?", core.EventRoleDeleted, false).First(&event).Error
	require.NoError(t, dberr, "the denied delete must write a Success=false audit event")
	assert.Contains(t, event.Description, "super_admin", "the audit description must name the target role")
}
