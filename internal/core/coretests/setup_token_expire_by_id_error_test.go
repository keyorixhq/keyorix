// setup_token_expire_by_id_error_test.go covers ExpireSetupTokenByID's two
// error-shaped branches (setup_token.go) -- setup_token_expire_audit_test.go
// (#1622) only exercises the found-and-expired success path. Untested before
// this file: an unknown ID (a no-op, matching the raw storage primitive's own
// long-standing idempotent semantics) and a genuine storage failure (which
// must surface as a wrapped error, not be swallowed like the not-found case).
//
// AUTH-ENDPOINT-OUTAGE-1: "unknown" is the typed not-found the real store returns
// (gorm.ErrRecordNotFound wrapped with %w), not any error whose text says "not
// found"; a storage fault is core.ErrStorageReadUnavailable, even when the driver
// text happens to contain "not found".
package coretests

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
)

func TestExpireSetupTokenByID_UnknownID_NoOp(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	ms.On("GetSetupTokenByID", mock.Anything, uint(404)).Return(nil, fmt.Errorf("not found: %w", gorm.ErrRecordNotFound))
	c := core.NewKeyorixCore(ms)
	err := c.ExpireSetupTokenByID(context.Background(), 404)
	require.NoError(t, err)
	ms.AssertNotCalled(t, "MarkSetupTokenExpired", mock.Anything, mock.Anything)
}

func TestExpireSetupTokenByID_GenuineStorageError_Surfaces(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	ms.On("GetSetupTokenByID", mock.Anything, uint(5)).Return(nil, errors.New("connection reset"))
	c := core.NewKeyorixCore(ms)
	err := c.ExpireSetupTokenByID(context.Background(), 5)
	require.Error(t, err)
	require.True(t, core.IsStorageReadUnavailable(err), "a read fault is typed: %v", err)
	ms.AssertNotCalled(t, "MarkSetupTokenExpired", mock.Anything, mock.Anything)
}

// A fault whose driver text contains "not found" is still a fault: it used to be
// matched by text and swallowed as "unknown ID", reporting success for an expiry
// that never ran.
func TestExpireSetupTokenByID_FaultWithNotFoundText_IsNotSwallowed(t *testing.T) {
	t.Parallel()
	ms := new(storagetest.MockStorage)
	ms.On("GetSetupTokenByID", mock.Anything, uint(6)).Return(nil, errors.New("storage failed: pq: relation \"setup_tokens\" not found"))
	c := core.NewKeyorixCore(ms)
	err := c.ExpireSetupTokenByID(context.Background(), 6)
	require.Error(t, err, "a fault is not an unknown ID")
	require.True(t, core.IsStorageReadUnavailable(err), "a read fault is typed: %v", err)
	ms.AssertNotCalled(t, "MarkSetupTokenExpired", mock.Anything, mock.Anything)
}
