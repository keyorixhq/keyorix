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
	// Grant the admin-context user (id 1) super_admin globally so core.Authorize
	// admits the admin tests; denied tests use an ungranted user id. A real row is
	// created for id 1 (not just the role_users grant) so a subsequently
	// CreateUser'd test user gets a distinct auto-increment id instead of
	// colliding with the admin-context identity — DeleteUser's last-admin guard
	// (#106) checks the target's OWN role set, so a collision would make it look
	// like the last admin is being deleted.
	h.CreateTestUser(t, "admin", 1)
	h.AssignUserRole(t, 1, 1, nil)
	return NewUserService(h.CoreService)
}

func adminCtx() context.Context {
	return authCtx(1, "admin", "users.write", "users.read", "users.delete")
}

func (svc *UserGRPCService) mustCreate(t *testing.T, username, email string) *pb.User {
	t.Helper()
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: username, Email: email, Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
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
		Username: "x", Email: "x@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestUserService_CreateUser_PermissionDenied(t *testing.T) {
	svc := newUserService(t)
	ctx := authCtx(7, "reader") // ungranted user → denied
	_, err := svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "x", Email: "x@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// A client-supplied account_state must be ignored: it's a server-derived lifecycle
// field (mirrors the HTTP CreateUser handler, whose request body has no
// account_state field at all), not something a caller — however privileged —
// should be able to self-set at creation. Requesting "password_reset_required" on
// the plain admin-set-password path (which always normalizes to "active") pins
// that the client's value never reaches the stored user.
func TestUserService_CreateUser_AccountStateIgnored(t *testing.T) {
	svc := newUserService(t)
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "bob", Email: "bob@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		AccountState: strPtr("password_reset_required"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	assert.Equal(t, "active", resp.GetUser().GetAccountState(), "client-supplied account_state must not be honored")
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

// TestUserService_CreateUser_RoleGrantRequiresAssign proves that atomic
// provisioning over gRPC enforces the same per-grant roles.assign check the HTTP
// handler does: a caller holding users.write but NOT roles.assign may create a
// plain user, but may not hand out a system role or a project role it could not
// assign directly. Without this gate a users.write holder could mint a super_admin
// account over gRPC (privilege escalation) even though the HTTP path forbids it.
func TestUserService_CreateUser_RoleGrantRequiresAssign(t *testing.T) {
	h := testhelper.NewRBACTestHelper(t)
	t.Cleanup(h.Cleanup)

	// A role that can create users but cannot assign roles — the realistic
	// "user administrator" persona that the bug let escalate.
	h.CreateTestRole(t, "user_provisioner", "Can create users, cannot assign roles", 50)
	_, err := h.SqlDB.Exec(`INSERT OR IGNORE INTO role_permissions (role_id, permission_id)
		SELECT r.id, p.id FROM roles r, permissions p
		WHERE r.name = 'user_provisioner' AND p.name = 'users.write'`)
	require.NoError(t, err)
	h.AssignUserRole(t, 8, 50, nil)

	svc := NewUserService(h.CoreService)
	ctx := authCtx(8, "provisioner")

	// Plain user creation (no grant) is still allowed by users.write alone.
	resp, err := svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "plain", Email: "plain@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())

	// Handing out a system role is denied — this is the privilege-escalation gate.
	_, err = svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "esc", Email: "esc@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		Role: strPtr("super_admin"),
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	// Handing out a project role is likewise denied.
	_, err = svc.CreateUser(ctx, &pb.CreateUserRequest{
		Username: "esc2", Email: "esc2@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		ProjectAssignments: []*pb.ProjectAssignment{{ProjectId: 1, Role: "editor"}},
	})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestUserService_CreateUser_AdminCanGrantRole confirms the new gate does not
// block a legitimately-privileged caller: a global admin (roles.assign via
// super_admin) can still provision a user with a system role atomically.
func TestUserService_CreateUser_AdminCanGrantRole(t *testing.T) {
	svc := newUserService(t)
	resp, err := svc.CreateUser(adminCtx(), &pb.CreateUserRequest{
		Username: "withrole", Email: "withrole@example.com", Password: strPtr("Qr7#Kp2$Lm5@Vn9!"),
		Role: strPtr("system_viewer"),
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
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
