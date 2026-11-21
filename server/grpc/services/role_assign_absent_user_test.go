package services

// ERRMAP-TAILS-NOV-6 item 3: gRPC parity for REST's POST /user-roles absent-target answer
// (TestAssignRole_AbsentTargetUser in server/http/handlers). AssignRole for a user id that
// does not exist is NotFound and writes no grant; a fault reading the target is Unavailable
// (REST 503), never Internal and never NotFound.

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

func TestRoleService_AssignRole_AbsentTargetUser(t *testing.T) {
	_, h := newRoleService(t)
	existing := h.CreateTestUser(t, "assign-absent-existing", 505)
	fs := faultstorage.NewFaultyStorage(h.CoreService.Storage(), nil)
	svc := NewRoleService(core.NewKeyorixCore(fs))
	const absent = uint32(999999)

	grants := func(user uint32) int {
		got, err := svc.GetUserRoles(roleAdminCtx(), &pb.GetUserRolesRequest{UserId: user})
		if status.Code(err) == codes.NotFound {
			return 0 // an absent user has no grants to list
		}
		require.NoError(t, err)
		return len(got.GetRoles())
	}

	// The "no orphan grant row" half is core's (ERRMAP-TAILS-NOV-4 item 3, counted in the
	// DB by TestAssignRole_AbsentTargetUser): GetUserRoles of an absent user is NotFound
	// either way, so it cannot show a stray row here.
	t.Run("an absent user is NotFound", func(t *testing.T) {
		_, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: absent, RoleId: viewerRoleID})
		assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
	})

	t.Run("a fault reading the target is Unavailable, and the grant is not written", func(t *testing.T) {
		fs.Arm(&faultstorage.FaultSpec{Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: errors.New("injected: read failed")})
		_, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(existing.ID)), RoleId: viewerRoleID})
		fired := fs.Fired()
		fs.Arm(nil)
		require.True(t, fired, "the GetUser read fault must be reached")
		assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)
		assert.Zero(t, grants(intToU32(int(existing.ID))))
	})

	t.Run("an existing user is still assigned", func(t *testing.T) {
		_, err := svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: intToU32(int(existing.ID)), RoleId: viewerRoleID})
		require.NoError(t, err)
		assert.EqualValues(t, 1, grants(intToU32(int(existing.ID))))
	})
}
