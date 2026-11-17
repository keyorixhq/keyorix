package services

// GRPC-OUTAGE-TAILS-1 item 2 (#3911): the gRPC scope resolvers tell a storage
// read FAULT from a real missing row, as REST has since #3861/#3888. A fault is
// Unavailable (retry); NotFound is only for a row that is really absent. Each
// fault test also checks the effect: nothing was changed by the refused call.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

var errScopeReadBoom = errors.New("boom: connection reset by peer") // not a transient-looking error

// authorizeShareScoped: the share row or its secret cannot be READ.
func TestShareService_AuthorizeShareScoped_ReadFaultIsUnavailable(t *testing.T) {
	for _, method := range []string{"GetShareRecord", "GetSecret"} {
		t.Run(method, func(t *testing.T) {
			r := newShareTestRig(t)
			rec := r.share(t, "read")
			fs := faultstorage.NewFaultyStorage(r.core.Storage(), nil)
			svc := NewShareService(core.NewKeyorixCore(fs))
			fs.Arm(&faultstorage.FaultSpec{Method: method, NthCall: 1, Kind: faultstorage.KindError, Err: errScopeReadBoom})

			_, err := svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
			require.True(t, fs.Fired(), "the RPC must reach %s", method)
			assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)

			_, err = svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{ShareId: rec.GetId(), Permission: "write"})
			assert.NotEqual(t, codes.NotFound, status.Code(err), "a read fault is not 'share not found': %v", err)

			// Effect: the refused revoke changed nothing, and with the fault gone it works.
			list, lerr := r.svc.ListSecretShares(ownerCtx(), &pb.ListSecretSharesRequest{SecretId: r.secretID})
			require.NoError(t, lerr)
			assert.Len(t, list.GetShares(), 1, "a refused revoke leaves the share in place")
			_, err = r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
			require.NoError(t, err)
		})
	}
}

// A share or secret that is really absent is still NotFound, not an outage.
func TestShareService_AuthorizeShareScoped_RealMissingIsNotFound(t *testing.T) {
	r := newShareTestRig(t)

	_, err := r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: 99999})
	assert.Equal(t, codes.NotFound, status.Code(err), "missing share: %v", err)
	assert.Equal(t, "share not found", status.Convert(err).Message())

	rec := r.share(t, "read")
	require.NoError(t, r.db.Unscoped().Delete(&models.SecretNode{}, r.secretID).Error)
	_, err = r.svc.RevokeShare(ownerCtx(), &pb.RevokeShareRequest{ShareId: rec.GetId()})
	assert.Equal(t, codes.NotFound, status.Code(err), "missing secret: %v", err)
}

// authorizeScopedTarget (dynamic-secret config): a caller who holds the permission
// globally is told to retry on a read fault, and NotFound only for an absent row.
func TestDynamicSecretService_ScopedTarget_ReadFaultIsUnavailable(t *testing.T) {
	svc := newDynamicTestRig(t)
	fs := faultstorage.NewFaultyStorage(svc.core.Storage(), nil)
	faulty := NewDynamicSecretService(core.NewKeyorixCore(fs))
	ctx := authCtx(1, "owner")

	fs.Arm(&faultstorage.FaultSpec{Method: "GetDynamicSecretConfig", NthCall: 1, Kind: faultstorage.KindError, Err: errScopeReadBoom})
	_, err := faulty.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: 1})
	require.True(t, fs.Fired(), "the RPC must reach GetDynamicSecretConfig")
	assert.Equal(t, codes.Unavailable, status.Code(err), "%v", err)

	// Fault gone, row really absent: NotFound for the global holder.
	_, err = faulty.GetConfig(ctx, &pb.GetDynamicConfigRequest{Id: 99999})
	assert.Equal(t, codes.NotFound, status.Code(err), "%v", err)
}
