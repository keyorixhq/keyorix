package core

// share_list_by_user_cap_test.go — REVIEW-3018: ListSharesByUser (the gRPC/CLI
// path) merges the received and owned lists, and each storage fetch is capped
// at maxUnboundedListRows with the rest silently cut off. A fetch that comes
// back at the cap cannot be told from a truncated one, so the merged list must
// be refused (ErrShareListOverCap), exactly like ListUserShareViews and the
// owner-scoped list, never returned shortened.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// fixedShareLists answers the two fetches ListSharesByUser merges with fixed
// lists, so a test can put either one exactly at the storage cap without
// inserting ten thousand rows. Every other method reaches inner.
func fixedShareLists(inner storage.Storage, received, owned []*models.ShareRecord) storage.Storage {
	return hooked(inner, &storeHooks{
		ListSharesByUser: func(storage.Storage, context.Context, uint, time.Time) ([]*models.ShareRecord, error) {
			return received, nil
		},
		ListSharesByOwner: func(storage.Storage, context.Context, uint, time.Time) ([]*models.ShareRecord, error) {
			return owned, nil
		},
	})
}

// shareRecords returns n distinct share records with ids starting at firstID.
func shareRecords(firstID, n int) []*models.ShareRecord {
	out := make([]*models.ShareRecord, n)
	for i := range out {
		out[i] = &models.ShareRecord{ID: uint(firstID + i), SecretID: 1, RecipientID: 2, OwnerID: 1, Permission: "read"}
	}
	return out
}

func TestListSharesByUser_RefusesAFetchAtTheCap(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name            string
		received, owned []*models.ShareRecord
	}{
		{"received at the cap", shareRecords(1, maxShareViewBatchSize), nil},
		{"owned at the cap", nil, shareRecords(1, maxShareViewBatchSize)},
		// Every share appears in both lists, so the merged list is no longer
		// than one fetch: the refusal must be decided per fetch, not on the
		// merged length.
		{"both at the cap, fully overlapping", shareRecords(1, maxShareViewBatchSize), shareRecords(1, maxShareViewBatchSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, _, _ := mustShare(t)
			c.storage = fixedShareLists(c.storage, tc.received, tc.owned)

			shares, err := c.ListSharesByUser(context.Background(), 1)
			require.ErrorIs(t, err, ErrShareListOverCap,
				"a fetch at the storage cap may be truncated; the merged list must be refused, not returned short")
			assert.Nil(t, shares)
		})
	}
}

// Positive control: one row under the cap in each fetch is listed in full, so
// the refusal above cannot pass by refusing everything.
func TestListSharesByUser_ListsBothFetchesUnderTheCap(t *testing.T) {
	t.Parallel()
	c, _, _ := mustShare(t)
	under := maxShareViewBatchSize - 1
	c.storage = fixedShareLists(c.storage, shareRecords(1, under), shareRecords(1+under, under))

	shares, err := c.ListSharesByUser(context.Background(), 1)
	require.NoError(t, err)
	assert.Len(t, shares, 2*under, "received and owned shares are merged by id, none dropped")
}
