package services

// ERRSTRING-CLASS-1 item 2: mapShareError answers InvalidArgument for the expiry
// refusal by sentinel (storage.ErrShareExpiryNotInFuture), not by the phrase "share
// expiry must be in the future" inside err.Error(). The real refusal keeps its class
// and text; an untyped error that merely carries the phrase is a server fault.

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

func TestMapShareError_UntypedExpiryPhraseIsInternal(t *testing.T) {
	got := mapShareError(errors.New("pq: value for column note: share expiry must be in the future"))
	assert.Equal(t, codes.Internal, status.Code(got), got.Error())
	assert.Equal(t, "share operation failed", status.Convert(got).Message())
}

func TestShareService_PastExpiryIsInvalidArgument(t *testing.T) {
	r := newShareTestRig(t)
	past := timestamppb.New(time.Now().Add(-time.Hour))

	_, err := r.svc.ShareSecret(ownerCtx(), &pb.ShareSecretRequest{
		SecretId: r.secretID, RecipientId: 2, Permission: "read", ExpiresAt: past,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
	assert.Equal(t, "share expiry must be in the future", status.Convert(err).Message())

	// The update path (a second core site) answers the same way.
	rec := r.share(t, "read")
	_, err = r.svc.UpdateSharePermission(ownerCtx(), &pb.UpdateSharePermissionRequest{
		ShareId: rec.GetId(), Permission: "read", ExpiresAt: past,
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err), err.Error())
}
