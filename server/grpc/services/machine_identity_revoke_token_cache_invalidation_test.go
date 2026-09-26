// machine_identity_revoke_token_cache_invalidation_test.go — regression coverage
// for the GRPC-track Finding #1 shape, single-token leg: a machine token
// revoked via the gRPC MachineIdentityService.RevokeMachineToken RPC (revoking
// one credential, not transitioning the whole identity) must stop
// authenticating over HTTP on the very next request, not linger in the
// middleware's positive auth cache for up to validTokenTTL (30s).
//
// Unlike TransitionMachineIdentity (internal/core/machine_identities.go,
// #r124), core.RevokeMachineToken does NOT evict the cache itself — its own
// doc comment says it returns the revoked token's hash so the CALLER can
// evict it (server/http/handlers/machine_identities.go's RevokeMachineToken
// handler does exactly that via middleware.InvalidateTokenCacheByHash). The
// gRPC RPC discarded that returned hash instead, on the mistaken premise that
// "gRPC has no auth cache" — true for gRPC's own auth, irrelevant to the
// separate HTTP-side cache a gRPC-originated revoke must still evict.
package services

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// TestGRPCRevokeMachineToken_EvictsHTTPAuthCacheImmediately drives the REAL
// gRPC RevokeMachineToken RPC (not core.RevokeMachineToken directly) to
// revoke a single machine credential, then asserts the SAME token is
// rejected on the very next HTTP request rather than being served from the
// middleware's up-to-30s positive cache.
func TestGRPCRevokeMachineToken_EvictsHTTPAuthCacheImmediately(t *testing.T) {
	svc, coreService := newMachineCacheTestRig(t)
	ctx := authCtx(1, "admin")

	m, err := svc.CreateMachineIdentity(ctx, &pb.CreateMachineIdentityRequest{
		ProjectId: 1, Name: "ci-runner-single-token", IdentityType: "ci",
	})
	require.NoError(t, err)

	issued, err := svc.IssueMachineToken(ctx, &pb.IssueMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), Name: "deploy",
	})
	require.NoError(t, err)
	token := issued.GetToken()

	// Populate the positive cache with a real HTTP request.
	require.Equal(t, http.StatusOK, machineAuthProbe(coreService, token),
		"machine token should authenticate before revocation")

	// Revoke via the REAL gRPC entry point — the single-credential leg of
	// Finding #1 (GRPC track step 0 inventory), distinct from the
	// whole-identity TransitionMachineIdentity path #2111 already covers.
	_, err = svc.RevokeMachineToken(ctx, &pb.RevokeMachineTokenRequest{
		ProjectId: 1, MachineId: m.GetId(), TokenId: issued.GetId(),
	})
	require.NoError(t, err)

	// Immediately (no sleep, no 30s wait): HTTP must reject it, not serve the
	// stale positive cache entry.
	assert.Equal(t, http.StatusUnauthorized, machineAuthProbe(coreService, token),
		"a machine token revoked via gRPC RevokeMachineToken must be rejected by HTTP immediately, not served from the positive auth cache")
}
