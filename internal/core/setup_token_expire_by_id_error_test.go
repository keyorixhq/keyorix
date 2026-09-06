// setup_token_expire_by_id_error_test.go covers ExpireSetupTokenByID's two
// error-shaped branches (setup_token.go) -- setup_token_expire_audit_test.go
// (#1622) only exercises the found-and-expired success path. Untested before
// this file: an unknown ID (a no-op, matching the raw storage primitive's own
// long-standing idempotent semantics) and a genuine storage failure (which
// must surface as a wrapped error, not be swallowed like the not-found case).
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestExpireSetupTokenByID_UnknownID_NoOp(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSetupTokenByID", mock.Anything, uint(404)).Return(nil, errors.New("setup token not found"))
	c := NewKeyorixCore(ms)
	err := c.ExpireSetupTokenByID(context.Background(), 404)
	require.NoError(t, err)
	ms.AssertNotCalled(t, "MarkSetupTokenExpired", mock.Anything, mock.Anything)
}

func TestExpireSetupTokenByID_GenuineStorageError_Surfaces(t *testing.T) {
	ms := new(MockStorage)
	ms.On("GetSetupTokenByID", mock.Anything, uint(5)).Return(nil, errors.New("connection reset"))
	c := NewKeyorixCore(ms)
	err := c.ExpireSetupTokenByID(context.Background(), 5)
	require.Error(t, err)
	ms.AssertNotCalled(t, "MarkSetupTokenExpired", mock.Anything, mock.Anything)
}
