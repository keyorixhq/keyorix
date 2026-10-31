package core

// storage_read_class_own_revoke_test.go — STORAGE-ERR-CLASS-2 item 1.
//
// A user revoking their OWN session / PAT folded ANY read error into "not found", so
// during a database outage the caller concluded the credential was already gone while
// it kept authenticating. A fault is now ErrStorageReadUnavailable; a true not-found
// and another user's id stay one identical "not found" answer (no existence oracle).

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestStorageReadClass_OwnRevoke(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)
			owner := w.user()
			other := w.user()

			t.Run("session", func(t *testing.T) {
				s := &models.Session{UserID: owner.ID, SessionToken: w.name("sess-hash"), CreatedAt: time.Now()}
				require.NoError(t, w.db.Create(s).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetSessionByID", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				err := c.RevokeOwnSession(ctx, owner.ID, s.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var n int64
				require.NoError(t, w.db.Model(&models.Session{}).Where("id = ?", s.ID).Count(&n).Error)
				assert.EqualValues(t, 1, n, "the revoke was never applied")

				faulty.Arm(nil)
				errGone := c.RevokeOwnSession(ctx, owner.ID, 9_999_999)
				errOther := c.RevokeOwnSession(ctx, other.ID, s.ID)
				require.Error(t, errGone)
				require.Error(t, errOther)
				assert.Equal(t, errGone.Error(), errOther.Error(), "absent and another user's session are one answer")
				assert.False(t, IsStorageReadUnavailable(errGone))
				assert.False(t, IsStorageReadUnavailable(errOther))

				require.NoError(t, c.RevokeOwnSession(ctx, owner.ID, s.ID), "the retried revoke succeeds")
				require.NoError(t, w.db.Model(&models.Session{}).Where("id = ?", s.ID).Count(&n).Error)
				assert.EqualValues(t, 0, n)
			})

			t.Run("PAT", func(t *testing.T) {
				p := &models.PersonalAccessToken{UserID: owner.ID, Name: "own-revoke", TokenHash: w.name("pat-hash"), TokenPrefix: "kx_pat_"}
				require.NoError(t, w.db.Create(p).Error)
				faulty.Arm(&faultstorage.FaultSpec{Method: "GetPersonalAccessTokenByID", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
				_, err := c.RevokeOwnPAT(ctx, owner.ID, p.ID)
				require.True(t, faulty.Fired())
				requireReadFault(t, err)
				var row models.PersonalAccessToken
				require.NoError(t, w.db.First(&row, p.ID).Error)
				assert.False(t, row.Revoked, "the revoke was never applied")

				faulty.Arm(nil)
				_, errGone := c.RevokeOwnPAT(ctx, owner.ID, 9_999_999)
				_, errOther := c.RevokeOwnPAT(ctx, other.ID, p.ID)
				require.Error(t, errGone)
				require.Error(t, errOther)
				assert.Equal(t, errGone.Error(), errOther.Error(), "absent and another user's token are one answer")
				assert.False(t, IsStorageReadUnavailable(errGone))
				assert.False(t, IsStorageReadUnavailable(errOther))

				hash, err := c.RevokeOwnPAT(ctx, owner.ID, p.ID)
				require.NoError(t, err, "the retried revoke succeeds")
				assert.Equal(t, p.TokenHash, hash)
			})
		})
	}
}
