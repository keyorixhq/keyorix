package store_test

import (
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRemoteNotificationChannelStubs_Unsupported verifies that all six
// RemoteStorage notification-channel methods return an error (remoteUnsupported)
// as documented in remote_notification_channels_completeness_test.go.
func TestRemoteNotificationChannelStubs_Unsupported(t *testing.T) {
	rs, err := store.NewRemoteStorage(testConfig("http://localhost:19997"))
	require.NoError(t, err)
	ctx := context.Background()

	_, err = rs.ListNotificationChannels(ctx)
	assert.Error(t, err)

	_, err = rs.GetNotificationChannel(ctx, 1)
	assert.Error(t, err)

	_, err = rs.GetNotificationChannelByName(ctx, "foo")
	assert.Error(t, err)

	err = rs.CreateNotificationChannel(ctx, nil)
	assert.Error(t, err)

	err = rs.UpdateNotificationChannel(ctx, nil)
	assert.Error(t, err)

	err = rs.DeleteNotificationChannel(ctx, 1)
	assert.Error(t, err)

	err = rs.UpdateNotificationRetryPolicy(ctx, 1, 3, 1000)
	assert.Error(t, err)
}
