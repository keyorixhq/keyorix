// filter_active_holders_sentinel_test.go — ERRLOSS-ACL-1 item 3: the last-admin
// guard's filterActiveHolders drops a holder only when GetUser says the account is
// positively gone (storage.ErrUserNotFound, which GetUser wraps for a soft-deleted
// row). Any other GetUser failure propagates, even when its text happens to contain
// "not found".
package core

import (
	"context"
	"errors"
	"testing"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFilterActiveHolders_SoftDeletedHolderIsDropped: a soft-deleted holder no
// longer counts and is not an error; a live one stays.
func TestFilterActiveHolders_SoftDeletedHolderIsDropped(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	require.NoError(t, db.Create(&models.User{ID: 501, Username: "live-admin", UsernameFolded: "live-admin", Email: "live@example.test", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.User{ID: 502, Username: "gone-admin", UsernameFolded: "gone-admin", Email: "gone@example.test", IsActive: true}).Error)
	require.NoError(t, db.Delete(&models.User{}, 502).Error)

	got, err := c.filterActiveHolders(ctx, map[uint]bool{501: true, 502: true})
	require.NoError(t, err)
	assert.Equal(t, map[uint]bool{501: true}, got)
}

// TestFilterActiveHolders_GetUserFailurePropagates: a GetUser failure that is not
// ErrUserNotFound must fail the resolution, not silently drop the holder, even when
// its text contains "not found" (the old text match dropped it).
func TestFilterActiveHolders_GetUserFailurePropagates(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c, db := newACLCore(t)
	require.NoError(t, db.Create(&models.User{ID: 503, Username: "admin-503", UsernameFolded: "admin-503", Email: "a503@example.test", IsActive: true}).Error)

	injected := errors.New(`pq: prepared statement "lookup_user" not found`)
	faulty := faultstorage.NewFaultyStorage(c.storage, &faultstorage.FaultSpec{
		Method: "GetUser", NthCall: 1, Kind: faultstorage.KindError, Err: injected,
	})
	c2 := newACLCoreWithStorage(c, faulty)

	got, err := c2.filterActiveHolders(ctx, map[uint]bool{503: true})
	require.True(t, faulty.Fired(), "the GetUser fault must have fired, or this case proves nothing")
	require.Error(t, err, "a GetUser failure must not read as 'holder soft-deleted'")
	assert.ErrorIs(t, err, injected)
	assert.Nil(t, got)
}
