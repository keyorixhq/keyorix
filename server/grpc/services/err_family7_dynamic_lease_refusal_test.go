package services

// CORE-ERR-FAMILY-7 item 2 (gRPC side): revoking or renewing a lease that is no longer
// active was an untyped core error, so mapDynamicError's default branch answered it
// Unavailable ("backend operation failed"), a retryable outage. It is FailedPrecondition
// now, with core's text.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestErrFamily7_DynamicLeaseNotActiveIsFailedPrecondition(t *testing.T) {
	svc := newDynamicTestRig(t)
	ctx := authCtx(1, "owner")
	cfg, err := svc.CreateConfig(ctx, dynamicCreateReq("lease-state"))
	require.NoError(t, err)
	cred, err := svc.IssueLease(ctx, &pb.IssueLeaseRequest{ConfigId: cfg.GetId()})
	require.NoError(t, err)
	_, err = svc.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: cred.GetLeaseId()})
	require.NoError(t, err)

	_, err = svc.RevokeLease(ctx, &pb.RevokeLeaseRequest{LeaseId: cred.GetLeaseId()})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
	assert.Contains(t, status.Convert(err).Message(), "lease is not active")

	_, err = svc.RenewLease(ctx, &pb.RenewLeaseRequest{LeaseId: cred.GetLeaseId(), TtlSeconds: 60})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err), err.Error())
}
