// machine_identity_issue_token_machine_caller_test.go — the gRPC
// IssueMachineToken RPC tags a machine caller (WithSelfMachineGranter and
// WithMachineCallerCredential from the request's bearer metadata), so core
// evaluates the ceiling against the calling machine and refuses a restricted,
// self-minting or unidentified caller. Drives the real RPC, not core directly.
package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// machineCallerRPCCtx is a machine principal as the auth interceptor resolves
// it, with the bearer metadata the request carried (bearer "" = none).
func machineCallerRPCCtx(machineID uint, bearer string) context.Context {
	ctx := machineAuthCtx(machineID, "grpc-caller")
	if bearer == "" {
		return ctx
	}
	return metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", "Bearer "+bearer))
}

func TestGRPCIssueMachineToken_MachineCaller(t *testing.T) {
	svc, coreService := newMachineCacheTestRig(t)
	admin := authCtx(1, "admin")

	caller, err := svc.CreateMachineIdentity(admin, &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: "grpc-caller", IdentityType: "ci"})
	require.NoError(t, err)
	peer, err := svc.CreateMachineIdentity(admin, &pb.CreateMachineIdentityRequest{ProjectId: 1, Name: "grpc-peer", IdentityType: "ci"})
	require.NoError(t, err)
	callerID, peerID := uint(caller.GetId()), peer.GetId()

	plain, err := svc.IssueMachineToken(admin, &pb.IssueMachineTokenRequest{ProjectId: 1, MachineId: caller.GetId(), Name: "plain"})
	require.NoError(t, err)
	restricted, err := coreService.IssueMachineToken(context.Background(), 1, callerID, 1, core.IssueMachineTokenParams{Name: "restricted", AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, err)
	// Role 1 bundles users.read + roles.assign; held at the project only.
	require.NoError(t, coreService.Storage().AssignMachineRole(context.Background(), callerID, 1, storage.Scope{ProjectID: 1}))

	// Tagged as itself with an unrestricted credential: allowed for a peer.
	// Before the tagging, the ceiling ran for user 0 and always refused.
	res, err := svc.IssueMachineToken(machineCallerRPCCtx(callerID, plain.GetToken()), &pb.IssueMachineTokenRequest{ProjectId: 1, MachineId: peerID, Name: "for-peer"})
	require.NoError(t, err)
	require.NotEmpty(t, res.GetToken())

	for _, tc := range []struct {
		name   string
		bearer string
		target uint32
	}{
		{"self-mint", plain.GetToken(), caller.GetId()},
		{"cidr-restricted caller", restricted.PlainToken, peerID},
		{"cidr-restricted self-mint", restricted.PlainToken, caller.GetId()},
		{"federated caller", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjaSJ9.c2ln", peerID},
		{"no bearer metadata", "", peerID},
	} {
		_, err := svc.IssueMachineToken(machineCallerRPCCtx(callerID, tc.bearer), &pb.IssueMachineTokenRequest{ProjectId: 1, MachineId: tc.target, Name: "escape"})
		require.Equal(t, codes.PermissionDenied, status.Code(err), "%s: %v", tc.name, err)
	}
}
