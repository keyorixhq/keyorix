package store_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteBulkAccess_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19998"))
	require.NoError(t, err)
	ctx := context.Background()

	err = rs.CreateRejectionReasonTemplate(ctx, nil)
	assert.Error(t, err)

	_, err = rs.ListRejectionReasonTemplates(ctx)
	assert.Error(t, err)

	err = rs.DeleteRejectionReasonTemplate(ctx, 1)
	assert.Error(t, err)

	_, err = rs.ListAccessRequestsByIDs(ctx, []uint{1})
	assert.Error(t, err)
}
