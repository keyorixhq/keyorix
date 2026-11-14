package services

// GRPC-OUTAGE-TAILS-1 item 1 (#4020): RemoveRole of a grant the subject does not
// hold, and AssignRole of one it already holds, are the caller's answers (REST:
// 404 and 409), not Internal. A real storage fault on the same call is NOT turned
// into either: it stays Internal ("role operation failed").

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// viewerRoleID is the seeded "viewer" role: not an admin-bypass role, so its
// removal reaches storage.RemoveRole (the admin roles take the
// RemoveGlobalAdminRoleGuarded path instead).
const viewerRoleID = 4

func TestRoleService_RemoveRole_GrantNotHeld_NotFound(t *testing.T) {
	svc, h := newRoleService(t)
	user := h.CreateTestUser(t, "never-granted", 502)

	_, err := svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: intToU32(int(user.ID)), RoleId: viewerRoleID})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
	assert.Equal(t, "role not assigned to user", status.Convert(err).Message())
}

func TestRoleService_AssignRole_AlreadyHeld_AlreadyExists(t *testing.T) {
	svc, h := newRoleService(t)
	user := h.CreateTestUser(t, "double-granted", 503)
	req := &pb.AssignRoleRequest{UserId: intToU32(int(user.ID)), RoleId: viewerRoleID}

	_, err := svc.AssignRole(roleAdminCtx(), req)
	require.NoError(t, err)
	_, err = svc.AssignRole(roleAdminCtx(), req)
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "%v", err)
	assert.Equal(t, "role already assigned to user", status.Convert(err).Message())
}

// A storage fault while removing a HELD grant is not "not assigned": it stays
// Internal, and the grant is still there afterwards (the effect, not the code).
func TestRoleService_RemoveRole_StorageFault_NotNotFound(t *testing.T) {
	_, h := newRoleService(t)
	user := h.CreateTestUser(t, "fault-removee", 504)
	fs := faultstorage.NewFaultyStorage(h.CoreService.Storage(), nil)
	svc := NewRoleService(core.NewKeyorixCore(fs))
	_, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(user.ID)), RoleId: viewerRoleID})
	require.NoError(t, err)

	fs.Arm(&faultstorage.FaultSpec{Method: "RemoveRole", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("boom")})
	_, err = svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: intToU32(int(user.ID)), RoleId: viewerRoleID})
	require.True(t, fs.Fired(), "the RPC must reach storage RemoveRole")
	assert.Equal(t, codes.Internal, status.Code(err), "%v", err)

	got, err := svc.GetUserRoles(roleAdminCtx(), &pb.GetUserRolesRequest{UserId: intToU32(int(user.ID))})
	require.NoError(t, err)
	assert.NotEmpty(t, got.GetRoles(), "a failed remove leaves the grant in place")
}
