package services

// secret_mutation_lookup_fault_test.go -- STORAGE-ERR-CLASS-4 item 3 (#3873).
//
// UpdateSecret and DeleteSecret authorize twice: the RPC gate (authorizeSecretScoped),
// then core's per-secret check (checkSecretPermission), whose RBAC fallback logged a
// FAILED permission lookup and fell through to "insufficient permissions". Over gRPC a
// transient outage there answered PermissionDenied, which no client retries. It is
// codes.Unavailable now; a plain denial and a non-transient lookup error stay
// PermissionDenied, and once the fault clears the same RPC succeeds.

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
	"github.com/keyorixhq/keyorix/internal/storage/store"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestSecretMutationRPC_SecondLookupFault_IsUnavailableThenRecovers(t *testing.T) {
	type rpc struct {
		name string
		call func(svc *SecretGRPCService, ctx context.Context, id uint32) error
	}
	rpcs := []rpc{
		{"UpdateSecret", func(svc *SecretGRPCService, ctx context.Context, id uint32) error {
			_, err := svc.UpdateSecret(ctx, &pb.UpdateSecretRequest{Id: id, Metadata: map[string]string{"k": "v"}})
			return err
		}},
		{"DeleteSecret", func(svc *SecretGRPCService, ctx context.Context, id uint32) error {
			_, err := svc.DeleteSecret(ctx, &pb.DeleteSecretRequest{Id: id})
			return err
		}},
	}
	for _, c := range rpcs {
		t.Run(c.name, func(t *testing.T) {
			r := newSecretTestRig(t)
			created := r.createSecret(t, authCtx(1, "owner", "secrets.write", "secrets.read"), "mutation-target", "v1")
			// A non-owner holding the global writer role: the owner shortcut does not apply,
			// so core's RBAC fallback does the second ResolveUserPermissionAt.
			require.NoError(t, r.db.Create(&models.User{ID: 3, Username: "editor", Email: "editor@example.com"}).Error)
			require.NoError(t, r.db.Create(&models.UserRole{UserID: 3, RoleID: writerRoleID}).Error)
			fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
			svc := NewSecretService(core.NewKeyorixCore(fs))
			ctx := authCtx(3, "editor")

			fs.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 2, Kind: faultstorage.KindError, Err: errAuthzDBDown})
			err := c.call(svc, ctx, created.GetId())
			require.True(t, fs.Fired(), "precondition: core's permission lookup must hit the injected fault")
			requireUnavailable(t, err)

			// A non-transient lookup error is not an outage: it stays a fail-closed denial.
			fs2 := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
			svc2 := NewSecretService(core.NewKeyorixCore(fs2))
			fs2.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 2, Kind: faultstorage.KindError, Err: errors.New("opaque lookup failure")})
			err = c.call(svc2, ctx, created.GetId())
			require.True(t, fs2.Fired())
			assert.Equal(t, codes.PermissionDenied, status.Code(err), "%v", err)

			// Nothing cached: with no fault the same RPC succeeds.
			require.NoError(t, c.call(svc, ctx, created.GetId()))
		})
	}
}

// authorizeScopedTarget's target fetch: a non-transient READ fault is Unavailable for a
// caller who holds the permission globally (the only ones a true miss answers NotFound),
// a true miss stays NotFound, and a caller without global standing keeps the uniform
// PermissionDenied of an absent target.
func TestSecretRPC_TargetFetchFault_IsUnavailableForGlobalHolder(t *testing.T) {
	r := newSecretTestRig(t)
	created := r.createSecret(t, authCtx(1, "owner", "secrets.write", "secrets.read"), "fetch-target", "v1")
	require.NoError(t, r.db.Create(&models.User{ID: 2, Username: "nobody", Email: "nobody@example.com"}).Error)
	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
	svc := NewSecretService(core.NewKeyorixCore(fs))
	scanFault := errors.New(`sql: Scan error on column index 3, name "project_id": converting NULL to uint is unsupported`)
	get := func(ctx context.Context, id uint32) error {
		_, err := svc.GetSecret(ctx, &pb.GetSecretRequest{Id: id})
		return err
	}

	fs.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: scanFault})
	err := get(authCtx(1, "owner"), created.GetId())
	require.True(t, fs.Fired())
	fs.Arm(nil)
	assert.Equal(t, codes.Unavailable, status.Code(err), "a read fault is not NotFound: %v", err)
	assert.NotContains(t, err.Error(), "project_id", "the driver cause must not reach the client")

	assert.Equal(t, codes.NotFound, status.Code(get(authCtx(1, "owner"), 999999)), "a true miss stays NotFound")

	fs.Arm(&faultstorage.FaultSpec{Method: "GetSecret", NthCall: 1, Kind: faultstorage.KindError, Err: scanFault})
	err = get(authCtx(2, "nobody"), created.GetId())
	require.True(t, fs.Fired())
	fs.Arm(nil)
	assert.Equal(t, codes.PermissionDenied, status.Code(err), "no existence signal for a caller without global standing: %v", err)
}
