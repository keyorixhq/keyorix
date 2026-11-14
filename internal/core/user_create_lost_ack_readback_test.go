package core

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// userCreateLanded (#3225) on each answer the read-back can get. The transaction
// side (commit-then-error on every user-create path) is driven end to end in
// server/faultops (TestPartialCommit_*); a read-back that itself fails cannot be
// combined with that fault there (one armed fault per case), so it is pinned here.
func TestUserCreateLanded_ReadBackOutcomes(t *testing.T) {
	ctx := context.Background()
	c, st := newBootstrappedCore(t)
	admin, err := st.GetUserByUsername(ctx, "admin")
	require.NoError(t, err)
	writeErr := errors.New("commit acknowledgement lost")

	t.Run("present row is landed", func(t *testing.T) {
		landed, answer := c.userCreateLanded(ctx, "test", &models.User{ID: admin.ID, Username: admin.Username}, writeErr)
		require.True(t, landed)
		require.NoError(t, answer)
	})
	t.Run("nothing inserted keeps the error", func(t *testing.T) {
		landed, answer := c.userCreateLanded(ctx, "test", nil, writeErr)
		require.False(t, landed)
		require.Same(t, writeErr, answer)
	})
	t.Run("positively absent row keeps the error", func(t *testing.T) {
		landed, answer := c.userCreateLanded(ctx, "test", &models.User{ID: admin.ID + 1000, Username: "ghost"}, writeErr)
		require.False(t, landed)
		require.Same(t, writeErr, answer)
	})
	t.Run("another account under the id is not ours", func(t *testing.T) {
		landed, answer := c.userCreateLanded(ctx, "test", &models.User{ID: admin.ID, Username: "someone-else"}, writeErr)
		require.False(t, landed)
		require.Same(t, writeErr, answer)
	})
	for name, spec := range map[string]faultstorage.FaultSpec{
		"read error":          {Kind: faultstorage.KindError, Err: errors.New("connection reset by peer")},
		"no row and no error": {Kind: faultstorage.KindError},
		"panic":               {Kind: faultstorage.KindPanic, Err: errors.New("driver panic")},
	} {
		t.Run("failed read-back is an unknown outcome/"+name, func(t *testing.T) {
			spec.Method, spec.NthCall = "GetUser", 1
			fs := faultstorage.NewFaultyStorage(st, &spec)
			landed, answer := NewKeyorixCore(fs).userCreateLanded(ctx, "test", &models.User{ID: admin.ID, Username: admin.Username}, writeErr)
			require.True(t, fs.Fired(), "premise: the read-back was faulted")
			require.False(t, landed, "an unreadable outcome never counts as landed (fail closed)")
			require.ErrorIs(t, answer, ErrUserCreateOutcomeUnknown)
			require.ErrorIs(t, answer, writeErr, "the transaction's own error stays classifiable")
		})
	}
}
