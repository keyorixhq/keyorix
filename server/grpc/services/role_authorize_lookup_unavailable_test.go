package services

// role_authorize_lookup_unavailable_test.go -- AUTHZ-OUTAGE-TAILS-1 item 2: the
// bundle-permission check in resolvePermissionIDs (CreateRole/UpdateRole) runs
// core.Authorize for each named permission. A FAILED lookup (PostgreSQL down) is
// codes.Unavailable like every other gRPC service (INV-MW-authorize-lookup-error-is-503),
// not Internal; an error that is not an outage stays Internal, and once the fault clears the same RPC succeeds.
//
// NthCall is 3, not 2: the G80 D1/known-01 fix (authorizeGlobalMutation) makes
// CreateRole issue two authz lookups (roles.read, then roles.write) before
// resolvePermissionIDs' own bundle-permission lookup, which is now the third
// ResolveUserPermissionAt call, not the second.

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

func TestRoleService_CreateRole_AuthorizeLookupFault(t *testing.T) {
	cases := []struct {
		name string
		err  error
		code codes.Code
		msg  string
	}{
		{"outage is Unavailable", errAuthzDBDown, codes.Unavailable, authorizeUnavailableMessage},
		{"non-outage error stays Internal", errors.New("boom"), codes.Internal, "failed to resolve actor authority"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, h := newRoleService(t)
			perm := somePermission(t, h)
			fs := faultstorage.NewFaultyStorage(h.CoreService.Storage(), nil)
			svc := NewRoleService(core.NewKeyorixCore(fs))
			// Calls 1-2 are authorizeGlobalMutation's roles.read then roles.write checks
			// (already mapped, G80 D1/known-01 fix); call 3 is the bundle-permission
			// check in resolvePermissionIDs, the line under test.
			fs.Arm(&faultstorage.FaultSpec{Method: "ResolveUserPermissionAt", NthCall: 3, Kind: faultstorage.KindError, Err: tc.err})

			req := &pb.CreateRoleRequest{Name: "outage-role", Description: "d", Permissions: []string{perm}}
			_, err := svc.CreateRole(roleAdminCtx(), req)
			require.True(t, fs.Fired(), "the RPC must reach the bundle-permission lookup")
			require.Error(t, err)
			assert.Equal(t, tc.code, status.Code(err), "%v", err)
			assert.Equal(t, tc.msg, status.Convert(err).Message())

			if tc.code == codes.Unavailable {
				_, err = svc.CreateRole(roleAdminCtx(), req)
				require.NoError(t, err, "nothing is cached: the retry succeeds once the fault clears")
			}
		})
	}
}
