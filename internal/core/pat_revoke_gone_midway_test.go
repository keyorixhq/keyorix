package core

// pat_revoke_gone_midway_test.go -- CORE-FAULT-TAILS-1 item 3: a token deleted between
// RevokeOwnPAT's ownership read and its revoke write (the retention purge, or any
// out-of-band delete) made the store answer an untyped "not found", which surfaced as a
// failed write (HTTP 500). It is now the uniform ErrPATNotFound, and nothing is audited
// as revoked.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// deleteBeforeRevoke hard-deletes token id just before the revoke's transaction opens,
// i.e. after RevokeOwnPAT has read and ownership-checked it.
func deleteBeforeRevoke(t *testing.T, w *c4World, id uint) storage.Storage {
	return storagetest.Hooked(w.core.storage, &storagetest.StoreHooks{
		WithTransaction: func(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error {
			require.NoError(t, w.db.Unscoped().Delete(&models.PersonalAccessToken{}, id).Error)
			return next.WithTransaction(ctx, fn)
		},
	})
}

func TestRevokeOwnPAT_DeletedMidRevokeIsNotFound(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			owner := w.user()
			mine, err := w.core.storage.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
				UserID: owner.ID, Name: "gone-midway", TokenHash: w.name("hash"), TokenPrefix: "kx_pat_",
			})
			require.NoError(t, err)

			c := NewKeyorixCore(deleteBeforeRevoke(t, w, mine.ID))
			hash, err := c.RevokeOwnPAT(ctx, owner.ID, mine.ID)
			assert.Empty(t, hash)
			require.ErrorIs(t, err, ErrPATNotFound, "a token gone before the revoke is not found, not a failed write")
			assert.False(t, IsStorageReadUnavailable(err))

			var revoked int64
			require.NoError(t, w.db.Model(&models.AuditEvent{}).Where("event_type = ?", EventPATRevoked).Count(&revoked).Error)
			assert.Zero(t, revoked, "nothing was revoked, so nothing is audited as revoked")
		})
	}
}
