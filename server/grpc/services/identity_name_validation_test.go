package services

import (
	"testing"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// IDENTITY-FOLD-SPACE-WIDTH over gRPC: the transport has no request-body
// validator, so the username/role-name rule in core is the only check, and its
// refusal must surface as InvalidArgument, not Internal.
var grpcSpoofedNames = []string{"ａｄｍｉｎ", "ad min", "admin ", " admin", "ad  min"}

func TestUserService_CreateUser_RejectsSpoofedUsername(t *testing.T) {
	svc := newUserService(t)
	for i, name := range grpcSpoofedNames {
		_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
			Username: name, Email: "spoof" + string(rune('a'+i)) + "@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		})
		require.Error(t, err, "%q accepted", name)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "%q: %v", name, err)
	}
	svc.mustCreate(t, "john.developer", "john@example.com") // control
}

func TestUserService_UpdateUser_RenameRejectsSpoofedUsername(t *testing.T) {
	svc := newUserService(t)
	created := svc.mustCreate(t, "erin", "erin@example.com")
	for _, name := range grpcSpoofedNames {
		_, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: created.GetId(), Username: strPtr(name)})
		require.Error(t, err, "%q accepted", name)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "%q: %v", name, err)
	}
	// Echoing the unchanged name back is not a rename.
	_, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{Id: created.GetId(), Username: strPtr("erin"), DisplayName: strPtr("Erin")})
	require.NoError(t, err)
}

func TestRoleService_CreateRole_RejectsSpoofedName(t *testing.T) {
	svc, h := newRoleService(t)
	perm := somePermission(t, h)
	for _, name := range []string{"ｏｐｓ_team", "ops team", "ops team ", " ops team", "ops  team", "ops.team"} {
		_, err := svc.CreateRole(roleAdminCtx(), &pb.CreateRoleRequest{
			Name: name, Description: "a valid description", Permissions: []string{perm},
		})
		require.Error(t, err, "%q accepted", name)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "%q: %v", name, err)
	}
}
