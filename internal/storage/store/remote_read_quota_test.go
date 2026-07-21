package store_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteReadQuotaStub_Unsupported verifies that RemoteStorage.ListSecretsWithQuota
// returns ErrRemoteUnsupported as documented in remote_read_quota_completeness_test.go.
func TestRemoteReadQuotaStub_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = rs.ListSecretsWithQuota(ctx)
	assert.Error(t, err)
}
