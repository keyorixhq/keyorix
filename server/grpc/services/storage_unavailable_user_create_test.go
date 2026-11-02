package services

// storage_unavailable_user_create_test.go — STORAGE-ERR-CLASS-2 item 2 (gRPC).
//
// UserService.CreateUser resolves the requested system role and project assignments
// before it writes. A failed role / project READ used to surface as an
// InvalidArgument "unknown role"; mapUserError now answers it Unavailable (retry).

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/keyorixhq/keyorix/internal/core"
)

func TestMapUserError_StorageReadFaultIsUnavailable(t *testing.T) {
	fault := core.ReadFault(errors.New("driver: connection reset by peer"))
	require.Error(t, fault)

	st, ok := status.FromError(mapUserError(fmt.Errorf("create user: %w", fault)))
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, core.StorageReadUnavailableMessage, st.Message())
	assert.NotContains(t, st.Message(), "connection reset", "the driver cause must not reach the client")

	// An absent role keeps its validation verdict.
	st, _ = status.FromError(mapUserError(errors.New(`Validation error: unknown role "nope"`)))
	assert.NotEqual(t, codes.Unavailable, st.Code())
}
