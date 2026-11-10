package services

// grpc_rest_parity_codes_test.go — REVOKE-AUTHORITY-TAILS-1 item 4: gRPC answers
// what REST answers for the same request.
//   - #4020: RemoveRole of a grant the subject does not hold is NotFound (REST 404),
//     AssignRole of one it already holds is AlreadyExists (REST 409); both were Internal.
//   - #3911: a NON-transient storage read fault in the gRPC scope resolvers
//     (authorizeShareScoped, authorizeScopedTarget) is Unavailable (REST 503), never
//     NotFound; a positive not-found stays NotFound. Transient (connection) faults are
//     TestShareRPC_AuthorizeLookupFault_IsUnavailable.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestRoleRPC_AssignmentStateCodesMatchREST(t *testing.T) {
	svc, h := newRoleService(t)
	user := h.CreateTestUser(t, "parity-target", 700)
	const roleID = 4 // the helper's ordinary "viewer" role: no admin-tier or last-admin path
	uid := intToU32(int(user.ID))

	_, err := svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: uid, RoleId: roleID})
	assert.Equal(t, codes.NotFound, status.Code(err), "removing a grant the user does not hold: %v", err)

	_, err = svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: uid, RoleId: roleID})
	require.NoError(t, err)
	_, err = svc.AssignRole(roleAdminCtx(), &pb.AssignRoleRequest{UserId: uid, RoleId: roleID})
	assert.Equal(t, codes.AlreadyExists, status.Code(err), "assigning a grant the user already holds: %v", err)

	_, err = svc.RemoveRole(roleAdminCtx(), &pb.RemoveRoleRequest{UserId: uid, RoleId: roleID})
	require.NoError(t, err, "removing a held grant still works")
}

// errNonTransientRead is a read fault that is not a connection error (a scan
// error, a corrupt row): core.IsAuthorizeTransient does not match it.
var errNonTransientRead = errors.New("sql: Scan error on column index 3: unsupported conversion")

func TestShareRPC_NonTransientReadFault_IsUnavailableNotNotFound(t *testing.T) {
	for _, lookup := range []string{"GetShareRecord", "GetSecret"} {
		t.Run(lookup, func(t *testing.T) {
			g := newAuthzOutageRig(t)
			share := &models.ShareRecord{SecretID: uint(g.secretID)}
			require.NoError(t, g.r.db.Create(share).Error)
			svc := &ShareGRPCService{core: core.NewKeyorixCore(g.fs)}
			for _, actor := range []*interceptors.UserContext{
				{UserID: 1, Username: "owner"},
				{UserID: 2, Username: "nobody"},
			} {
				g.fs.Arm(&faultstorage.FaultSpec{Method: lookup, NthCall: 1, Kind: faultstorage.KindError, Err: errNonTransientRead})
				err := svc.authorizeShareScoped(context.Background(), actor, share.ID, "secrets.write")
				require.True(t, g.fs.Fired())
				assert.Equal(t, codes.Unavailable, status.Code(err), "%s: a read fault is not 'share not found': %v", actor.Username, err)
				assert.Equal(t, core.StorageReadUnavailableMessage, status.Convert(err).Message(), "fixed text, no driver error")
			}
			g.fs.Arm(nil)

			err := svc.authorizeShareScoped(context.Background(), &interceptors.UserContext{UserID: 1, Username: "owner"}, share.ID+1000, "secrets.write")
			assert.Equal(t, codes.NotFound, status.Code(err), "an absent share is still NotFound")
		})
	}
}

func TestAuthorizeScopedTarget_NonTransientReadFault(t *testing.T) {
	_, h := newRoleService(t) // user 1 holds super_admin globally
	cs := h.CoreService
	ctx := context.Background()
	holder := &interceptors.UserContext{UserID: 1, Username: "admin"}
	other := &interceptors.UserContext{UserID: 7, Username: "nobody"}

	err := authorizeScopedTarget(ctx, cs, holder, "secrets.read", errNonTransientRead, core.Scope{}, "secret not found")
	assert.Equal(t, codes.Unavailable, status.Code(err), "a global holder is told to retry a read fault: %v", err)
	err = authorizeScopedTarget(ctx, cs, other, "secrets.read", errNonTransientRead, core.Scope{}, "secret not found")
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "anyone else keeps the uniform denial (no existence signal)")
}
