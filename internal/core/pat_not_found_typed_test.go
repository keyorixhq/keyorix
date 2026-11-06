package core

// pat_not_found_typed_test.go — STORAGE-ERR-CLASS-5 item 3: RevokeOwnPAT's not-found is
// ErrPATNotFound (a sentinel, not text), and a read fault or a failed write is not it.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRevokeOwnPAT_NotFoundIsTypedAndFaultIsNot(t *testing.T) {
	for _, backend := range c4Backends(t) {
		t.Run(backend, func(t *testing.T) {
			w := newC4World(t, backend)
			ctx := context.Background()
			owner, other := w.user(), w.user()
			mine, err := w.core.storage.CreatePersonalAccessToken(ctx, &models.PersonalAccessToken{
				UserID: owner.ID, Name: "mine", TokenHash: w.name("hash"), TokenPrefix: "kx_pat_",
			})
			require.NoError(t, err)
			faulty := faultstorage.NewFaultyStorage(w.core.storage, nil)
			c := NewKeyorixCore(faulty)

			_, errAbsent := c.RevokeOwnPAT(ctx, owner.ID, 9_999_999)
			_, errOther := c.RevokeOwnPAT(ctx, other.ID, mine.ID)
			_, errZero := c.RevokeOwnPAT(ctx, owner.ID, 0)
			_, errNoUser := c.RevokeOwnPAT(ctx, 0, mine.ID) // a machine principal has no user id
			for name, err := range map[string]error{"absent": errAbsent, "another user's": errOther, "id 0": errZero, "user 0": errNoUser} {
				assert.ErrorIs(t, err, ErrPATNotFound, name)
				assert.False(t, IsStorageReadUnavailable(err), name)
			}

			faulty.Arm(&faultstorage.FaultSpec{Method: "GetPersonalAccessTokenByID", NthCall: 1, Kind: faultstorage.KindError, Err: assert.AnError})
			_, errFault := c.RevokeOwnPAT(ctx, owner.ID, mine.ID)
			require.True(t, faulty.Fired())
			assert.ErrorIs(t, errFault, ErrStorageReadUnavailable)
			assert.NotErrorIs(t, errFault, ErrPATNotFound, "a read fault is no verdict on the token")
			faulty.Arm(nil)

			hash, err := c.RevokeOwnPAT(ctx, owner.ID, mine.ID)
			require.NoError(t, err)
			assert.NotEmpty(t, hash)
		})
	}
}
