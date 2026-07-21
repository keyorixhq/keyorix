// remote_retention_override_test.go — direct call test for the RemoteStorage
// SetRetentionOverride stub.
package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteStorage_SetRetentionOverride_Unsupported verifies that calling
// SetRetentionOverride on RemoteStorage returns ErrRemoteUnsupported.
// Override management is always server-side; this stub must never silently succeed.
func TestRemoteStorage_SetRetentionOverride_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)

	err = rs.SetRetentionOverride(context.Background(), 1, 30)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, store.ErrRemoteUnsupported),
		"expected ErrRemoteUnsupported, got %v", err)
}
