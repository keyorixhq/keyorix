package services

// #4546 (L-2 of REVIEW-4613-DEEP-1): RevokeBreakGlass now reads the acting account
// first (requireActorActive). A fault in that read is typed
// core.ErrStorageReadUnavailable and REST answers it 503; gRPC answered it Internal
// "break-glass operation failed". It is now retryable Unavailable with the fixed
// storage_unavailable text and ErrorInfo, and the driver text stays in the log.

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestBreakGlassError_StorageReadFaultIsUnavailable(t *testing.T) {
	fault := core.ReadFault(errors.New("pq: connection reset by peer on users"))
	require.True(t, core.IsStorageReadUnavailable(fault))

	st := status.Convert(breakGlassError(fmt.Errorf("retrieval failed: resolving the acting account: %w", fault)))
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, core.StorageReadUnavailableMessage, st.Message())
	assert.NotContains(t, st.Message(), "pq:", "no storage text reaches the client")
	var reason string
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			reason = info.GetReason()
		}
	}
	assert.Equal(t, storageUnavailableReason, reason)
}
