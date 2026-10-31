package services

// authorize_lookup_unavailable_test.go -- gRPC half of INV-MW-authorize-lookup-error-is-503
// (AUTHZ-OUTAGE-503-1, #3458). A FAILED permission lookup (PostgreSQL down, request
// deadline) is codes.Unavailable, not PermissionDenied: the client retries Unavailable
// and does not retry a denial. A plain denial stays PermissionDenied, an error that is
// not an outage stays a fail-closed PermissionDenied, a PAT restriction denies with no
// storage access, and once the fault clears the same RPC succeeds (nothing cached).
//
// The fault is injected with internal/faultstorage on the exact permission-resolving
// read of each principal kind; the injected error is a structural connection error
// (a *net.OpError), never matched by text.

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/keyorixhq/keyorix/server/grpc/interceptors"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

var errAuthzDBDown = &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}

type authzOutageRig struct {
	r         *secretTestRig
	fs        *faultstorage.FaultyStorage
	svc       *SecretGRPCService
	secretID  uint32
	machineID uint
}

func newAuthzOutageRig(t *testing.T) *authzOutageRig {
	t.Helper()
	r := newSecretTestRig(t)
	created := r.createSecret(t, authCtx(1, "owner", "secrets.write", "secrets.read"), "outage-target", "v1")

	require.NoError(t, r.db.Create(&models.User{ID: 2, Username: "nobody", Email: "nobody@example.com"}).Error)
	machine := &models.MachineIdentity{ProjectID: 1, Name: "outage-bot", IdentityType: "service", State: "active"}
	require.NoError(t, r.db.Create(machine).Error)
	require.NoError(t, r.db.Create(&models.MachineIdentityRole{MachineIdentityID: machine.ID, RoleID: writerRoleID}).Error)

	fs := faultstorage.NewFaultyStorage(store.NewLocalStorage(r.db), nil)
	return &authzOutageRig{
		r: r, fs: fs, svc: NewSecretService(core.NewKeyorixCore(fs)),
		secretID: created.GetId(), machineID: machine.ID,
	}
}

func (g *authzOutageRig) arm(method string, err error) {
	g.fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: err})
}

type authzOutagePrincipal struct {
	name   string
	ctx    func(g *authzOutageRig) context.Context
	lookup string
}

func authzOutagePrincipals() []authzOutagePrincipal {
	return []authzOutagePrincipal{
		{"user", func(*authzOutageRig) context.Context { return authCtx(1, "owner") }, "ResolveUserPermissionAt"},
		{"machine", func(g *authzOutageRig) context.Context {
			return context.WithValue(context.Background(), interceptors.GetUserContextKey(),
				&interceptors.UserContext{ActorType: core.ActorTypeMachine, MachineIdentityID: g.machineID, Username: "outage-bot"})
		}, "ResolveMachinePermissionAt"},
	}
}

func listReq() *pb.ListSecretsRequest {
	return &pb.ListSecretsRequest{ProjectId: proto.Uint32(1), EnvironmentId: proto.Uint32(1)}
}

func requireUnavailable(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err), "a lookup outage is Unavailable, not PermissionDenied: %v", err)
	assert.Equal(t, "authorization temporarily unavailable, please retry", status.Convert(err).Message(), "fixed message, no storage error text")
}

// TestSecretRPC_AuthorizeLookupFault_IsUnavailableThenRecovers covers the three
// authorize shapes: scoped create/list (authorizeScoped inline) and the per-secret
// gate (authorizeSecretScoped), the latter for both the permission lookup and the
// secret fetch.
func TestSecretRPC_AuthorizeLookupFault_IsUnavailableThenRecovers(t *testing.T) {
	type rpc struct {
		name   string
		lookup func(p authzOutagePrincipal) string
		call   func(g *authzOutageRig, ctx context.Context) error
	}
	same := func(p authzOutagePrincipal) string { return p.lookup }
	rpcs := []rpc{
		{"ListSecrets", same, func(g *authzOutageRig, ctx context.Context) error {
			_, err := g.svc.ListSecrets(ctx, listReq())
			return err
		}},
		{"CreateSecret", same, func(g *authzOutageRig, ctx context.Context) error {
			_, err := g.svc.CreateSecret(ctx, &pb.CreateSecretRequest{
				Name: "never-created", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password"})
			return err
		}},
		{"GetSecret/permission", same, func(g *authzOutageRig, ctx context.Context) error {
			_, err := g.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: g.secretID})
			return err
		}},
		{"GetSecret/fetch", func(authzOutagePrincipal) string { return "GetSecret" }, func(g *authzOutageRig, ctx context.Context) error {
			_, err := g.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: g.secretID})
			return err
		}},
	}
	for _, p := range authzOutagePrincipals() {
		for _, c := range rpcs {
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				g := newAuthzOutageRig(t)
				ctx := p.ctx(g)

				g.arm(c.lookup(p), errAuthzDBDown)
				err := c.call(g, ctx)
				require.True(t, g.fs.Fired(), "precondition: the lookup must hit the injected fault")
				requireUnavailable(t, err)

				if c.name == "CreateSecret" {
					var n int64
					require.NoError(t, g.r.db.Model(&models.SecretNode{}).Where("name = ?", "never-created").Count(&n).Error)
					assert.Zero(t, n, "the refused write left nothing behind")
				}

				err = c.call(g, ctx)
				if c.name == "ListSecrets" && p.name == "machine" {
					// The machine list path reads tables this rig does not migrate, so the
					// RPC itself ends Internal after authorization; what recovery must show
					// is that the gate no longer refuses.
					assert.NotContains(t, []codes.Code{codes.Unavailable, codes.PermissionDenied}, status.Code(err),
						"after the fault clears the gate admits the request: %v", err)
					return
				}
				require.NoError(t, err, "after the fault clears the same RPC succeeds")
			})
		}
	}
}

// TestSecretRPC_PlainDenialStaysPermissionDenied: a caller holding nothing is still
// PermissionDenied with the unchanged message, on every authorize shape.
func TestSecretRPC_PlainDenialStaysPermissionDenied(t *testing.T) {
	g := newAuthzOutageRig(t)
	ctx := authCtx(2, "nobody")

	_, err := g.svc.ListSecrets(ctx, listReq())
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, "insufficient permissions to list secrets", status.Convert(err).Message())

	_, err = g.svc.CreateSecret(ctx, &pb.CreateSecretRequest{Name: "x", Value: "v", ProjectId: 1, EnvironmentId: 1, Type: "password"})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	_, err = g.svc.GetSecret(ctx, &pb.GetSecretRequest{Id: g.secretID})
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Equal(t, "insufficient permissions", status.Convert(err).Message())
}

// TestSecretRPC_NonTransientLookupErrorStaysPermissionDenied: an error that is not an
// outage stays a fail-closed denial.
func TestSecretRPC_NonTransientLookupErrorStaysPermissionDenied(t *testing.T) {
	for _, p := range authzOutagePrincipals() {
		t.Run(p.name, func(t *testing.T) {
			g := newAuthzOutageRig(t)
			g.arm(p.lookup, errors.New("role resolution returned no result"))
			_, err := g.svc.ListSecrets(p.ctx(g), listReq())
			require.True(t, g.fs.Fired())
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

// TestSecretRPC_RestrictedPATStaysPermissionDeniedWithoutStorage: a PAT whose
// restriction disallows the permission is denied before any storage access, so an
// armed fault never fires and the answer is not Unavailable.
func TestSecretRPC_RestrictedPATStaysPermissionDeniedWithoutStorage(t *testing.T) {
	g := newAuthzOutageRig(t)
	g.arm("ResolveUserPermissionAt", errAuthzDBDown)
	ctx := core.WithPATRestriction(authCtx(1, "owner"), &core.PATRestriction{Permissions: []string{"projects.read"}})

	_, err := g.svc.ListSecrets(ctx, listReq())
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.False(t, g.fs.Fired(), "the restriction denies before any storage access")
}

// TestSecretRPC_NotFoundProbeLookupFault_IsUnavailable: a missing target makes the
// gate probe the caller's global permission; an outage in THAT lookup is Unavailable.
func TestSecretRPC_NotFoundProbeLookupFault_IsUnavailable(t *testing.T) {
	g := newAuthzOutageRig(t)
	g.arm("ResolveUserPermissionAt", errAuthzDBDown)
	_, err := g.svc.GetSecret(authCtx(1, "owner"), &pb.GetSecretRequest{Id: g.secretID + 1000})
	require.True(t, g.fs.Fired())
	requireUnavailable(t, err)

	_, err = g.svc.GetSecret(authCtx(1, "owner"), &pb.GetSecretRequest{Id: g.secretID + 1000})
	assert.Equal(t, codes.NotFound, status.Code(err), "after the fault clears a global holder gets NotFound again")
}

// TestShareRPC_AuthorizeLookupFault_IsUnavailable: authorizeShareScoped, for the
// permission lookup and for the share / secret fetches.
func TestShareRPC_AuthorizeLookupFault_IsUnavailable(t *testing.T) {
	for _, lookup := range []string{"ResolveUserPermissionAt", "GetShareRecord", "GetSecret"} {
		t.Run(lookup, func(t *testing.T) {
			g := newAuthzOutageRig(t)
			share := &models.ShareRecord{SecretID: uint(g.secretID)}
			require.NoError(t, g.r.db.Create(share).Error)
			svc := &ShareGRPCService{core: core.NewKeyorixCore(g.fs)}
			actor := &interceptors.UserContext{UserID: 1, Username: "owner"}

			g.arm(lookup, errAuthzDBDown)
			err := svc.authorizeShareScoped(context.Background(), actor, share.ID, "secrets.write")
			require.True(t, g.fs.Fired())
			requireUnavailable(t, err)

			require.NoError(t, svc.authorizeShareScoped(context.Background(), actor, share.ID, "secrets.write"),
				"after the fault clears the same check succeeds")

			denied := &interceptors.UserContext{UserID: 2, Username: "nobody"}
			err = svc.authorizeShareScoped(context.Background(), denied, share.ID, "secrets.write")
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}
