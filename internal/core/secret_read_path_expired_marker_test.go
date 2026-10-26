package core

// #3568: the HTTP read (GET /secrets/{id}?include_value=true) goes through
// GetSecretForRead, which judges expiry in unexpiredSecret before the value gate ever
// runs. That check must carry the clear-synced-copies marker the same way the value gate
// does (secret_suspend_clear_copies_expired_test.go), or the SecretExpired refusal a
// workload sees drops details.clear_synced_copies. GetSecret and GetSecretByName share
// the same check.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func metadataRefusal(t *testing.T, err error) SecretReadRefusal {
	t.Helper()
	require.Error(t, err)
	refusal, ok := ClassifySecretReadRefusal(err)
	require.True(t, ok, "must classify as a refusal, got %v", err)
	require.Equal(t, SecretReadRefusalCodeExpired, refusal.Code)
	return refusal
}

func TestUnexpiredSecret_CarriesClearMarkerOnReadPath(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("expired and suspended with the marker: GetSecret and GetSecretByName carry it", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "leaked", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		expireSecretNow(t, db, id)

		_, err = c.GetSecret(ctx, id)
		assert.True(t, metadataRefusal(t, err).ClearSyncedCopies)

		node, err := c.storage.GetSecret(ctx, id)
		require.NoError(t, err)
		_, err = c.GetSecretByName(ctx, node.Name, node.ProjectID, node.EnvironmentID)
		assert.True(t, metadataRefusal(t, err).ClearSyncedCopies)
	})

	t.Run("expired only: no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		expireSecretNow(t, db, id)
		_, err := c.GetSecret(ctx, id)
		assert.False(t, metadataRefusal(t, err).ClearSyncedCopies)
	})

	t.Run("expired and suspended without the marker: no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecret(ctx, id, 1, "maintenance")
		require.NoError(t, err)
		expireSecretNow(t, db, id)
		_, err = c.GetSecret(ctx, id)
		assert.False(t, metadataRefusal(t, err).ClearSyncedCopies)
	})

	t.Run("expired and a stale marker on a resumed (active) secret: no marker", func(t *testing.T) {
		c, id, db := newSuspendFixture(t)
		_, err := c.SuspendSecretWithOptions(ctx, id, 1, "", SuspendOptions{ClearSyncedCopies: true})
		require.NoError(t, err)
		_, err = c.ResumeSecret(ctx, id, 1)
		require.NoError(t, err)
		expireSecretNow(t, db, id)
		_, err = c.GetSecret(ctx, id)
		assert.False(t, metadataRefusal(t, err).ClearSyncedCopies)
	})
}
