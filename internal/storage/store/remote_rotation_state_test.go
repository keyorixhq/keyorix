// remote_rotation_state_test.go — exercises the two RemoteStorage stubs
// introduced by the rotation-state feature: GetRotationPolicyBySecret and
// UpdateRotationState. Both are intentionally server-side only (see
// remote_rotation_state_completeness_test.go) so each returns
// ErrRemoteUnsupported immediately — no HTTP server is needed.
package store_test

import (
	"context"
	"testing"

	"errors"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRotationStateRemote(t *testing.T) *store.RemoteStorage {
	t.Helper()
	rs, err := store.NewRemoteStorage(testConfig("http://127.0.0.1:1"))
	require.NoError(t, err)
	return rs
}

// TestRemoteGetRotationPolicyBySecret_ReturnsUnsupported verifies that calling
// GetRotationPolicyBySecret on a RemoteStorage returns ErrRemoteUnsupported.
func TestRemoteGetRotationPolicyBySecret_ReturnsUnsupported(t *testing.T) {
	rs := newRotationStateRemote(t)
	_, err := rs.GetRotationPolicyBySecret(context.Background(), 1)
	require.Error(t, err)
	assert.ErrorContains(t, err, "GetRotationPolicyBySecret")
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"expected errors.Is(err, ErrRemoteUnsupported)")
}

// TestRemoteUpdateRotationState_ReturnsUnsupported verifies that calling
// UpdateRotationState on a RemoteStorage returns ErrRemoteUnsupported.
func TestRemoteUpdateRotationState_ReturnsUnsupported(t *testing.T) {
	rs := newRotationStateRemote(t)
	err := rs.UpdateRotationState(context.Background(), 1, "succeeded", "")
	require.Error(t, err)
	assert.ErrorContains(t, err, "UpdateRotationState")
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"expected errors.Is(err, ErrRemoteUnsupported)")
}
