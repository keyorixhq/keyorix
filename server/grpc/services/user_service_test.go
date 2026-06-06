package services

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/testhelper"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newUserService builds a UserService over the RBAC test helper, which seeds the
// standard system roles (system_viewer) that atomic user creation requires.
func newUserService(t *testing.T) *UserGRPCService {
	t.Helper()
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)
	return NewUserService(h.CoreService)
}

func adminCtx() context.Context {
	return authCtx(1, "admin", "users.write", "users.read", "users.delete")
}

func (svc *UserGRPCService) mustCreate(t *testing.T, username, email string) *pb.User {
	t.Helper()
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: username, Email: email, Password: strPtr("password123"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	return resp.GetUser()
}

func TestUserService_CreateUser_Password(t *testing.T) {
	svc := newUserService(t)
	u := svc.mustCreate(t, "alice", "alice@example.com")
	assert.NotZero(t, u.GetId())
	assert.Equal(t, "alice", u.GetUsername())
	assert.Equal(t, "alice@example.com", u.GetEmail())
	assert.Equal(t, "alice", u.GetDisplayName()) // defaulted from username
}

func TestUserService_CreateUser_Unauthenticated(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(context.Background(), &pb.CreateUserRequest{
		Username: "x", Email: "x@example.com", Password: strPtr("password123"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUserService_CreateUser_PermissionDenied(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(1, "reader", "users.read") // no write
	_, err := svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "x", Email: "x@example.com", Password: strPtr("password123"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

func TestUserService_CreateUser_MissingFields(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{Email: "x@example.com"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUserService_CreateUser_PasswordRequiredByDefault(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "nopass", Email: "nopass@example.com",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUserService_CreateUser_RoleWithSetupLinkRejected(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "bob", Email: "bob@example.com",
		DeliverSetupLink: true, Role: strPtr("system_viewer"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUserService_CreateUser_BothCredentialModesRejected(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "carol", Email: "carol@example.com",
		DeliverSetupLink: true, GenerateOneTimePassword: true,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestUserService_GetUser(t *testing.T) {
	svc := newUserService(t)
	created := svc.mustCreate(t, "dave", "dave@example.com")

	got, err := svc.GetUser(adminCtx(), &pb.GetUserRequest{Id: created.GetId()})
	require.NoError(t, err)
	assert.Equal(t, created.GetId(), got.GetId())
	assert.Equal(t, "dave", got.GetUsername())
}

func TestUserService_GetUser_NotFound(t *testing.T) {
	svc := newUserService(t)
	_, err := svc.GetUser(adminCtx(), &pb.GetUserRequest{Id: 99999})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestUserService_UpdateUser(t *testing.T) {
	svc := newUserService(t)
	created := svc.mustCreate(t, "erin", "erin@example.com")

	updated, err := svc.UpdateUser(adminCtx(), &pb.UpdateUserRequest{
		Id: created.GetId(), DisplayName: strPtr("Erin Updated"),
	})
	require.NoError(t, err)
	assert.Equal(t, "Erin Updated", updated.GetDisplayName())
}

func TestUserService_DeleteUser(t *testing.T) {
	svc := newUserService(t)
	created := svc.mustCreate(t, "frank", "frank@example.com")

	_, err := svc.DeleteUser(adminCtx(), &pb.DeleteUserRequest{Id: created.GetId()})
	require.NoError(t, err)

	_, err = svc.GetUser(adminCtx(), &pb.GetUserRequest{Id: created.GetId()})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestUserService_ListUsers(t *testing.T) {
	svc := newUserService(t)
	svc.mustCreate(t, "grace", "grace@example.com")

	resp, err := svc.ListUsers(adminCtx(), &pb.ListUsersRequest{})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(resp.GetUsers()), 1)
	assert.GreaterOrEqual(t, resp.GetTotal(), uint32(1))
}
