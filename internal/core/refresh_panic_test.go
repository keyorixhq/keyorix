package core

// #3968: a storage panic inside RefreshSession takes the call's error path.
// ErrRefreshNotEvaluated is what makes the HTTP handler hand the per-IP login
// slot back, so it must appear for the pre-verdict lookup's panic and for
// nothing after the verdict: a post-verdict panic that came back as "not
// evaluated" would refund the slot of a request that hit a live token, and a
// panicking store would then make valid tokens cheaper than wrong ones (#2880).

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRefreshSession_PostVerdictPanicIsNotEvaluatedOnlyBeforeTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		method       string
		notEvaluated bool // pre-verdict: the slot goes back
		readFault    bool // post-verdict read: ErrStorageReadUnavailable (503)
	}{
		{"GetSessionAny", true, false},
		{"GetUser", false, true},
		{"RotateSession", false, false},
	} {
		t.Run(tc.method, func(t *testing.T) {
			t.Parallel()
			c, st := newBootstrappedCore(t)
			ctx := context.Background()
			old, _, err := c.Login(ctx, &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
			require.NoError(t, err)
			fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
				Method: tc.method, NthCall: 1, Kind: faultstorage.KindPanic,
				// A payload that reads as "not found" must not steer the verdict:
				// a panic is never a definitive no-such-session/user.
				Err: fmt.Errorf("injected panic: %w", storage.ErrSessionNotFound),
			})
			c.storage = fs

			var session *models.Session
			require.NotPanics(t, func() { session, err = c.RefreshSession(ctx, old.SessionToken) })
			require.True(t, fs.Fired(), "the armed %s panic must have fired", tc.method)
			require.Error(t, err)
			assert.Nil(t, session)
			assert.Equal(t, tc.notEvaluated, errors.Is(err, ErrRefreshNotEvaluated),
				"%s panic: ErrRefreshNotEvaluated (slot refund) must mark exactly the pre-verdict lookup: %v", tc.method, err)
			assert.Equal(t, tc.readFault, errors.Is(err, ErrStorageReadUnavailable),
				"%s panic: must take its error twin's classification: %v", tc.method, err)

			// The panic replaced the call, so the token is still the live one.
			_, err = st.GetSession(ctx, old.SessionToken)
			assert.NoError(t, err, "a refused refresh must not retire the presented token")
		})
	}
}

// A panic in the reuse path's hash listing must not skip the family revocation:
// the error kind still revokes, so the panic kind must too.
func TestRefreshSession_ReuseHashListingPanicStillRevokesTheFamily(t *testing.T) {
	t.Parallel()
	c, st := newBootstrappedCore(t)
	ctx := context.Background()
	old, _, err := c.Login(ctx, &LoginRequest{Username: "admin", Password: undeliveredTestPassword})
	require.NoError(t, err)
	fresh, err := c.RefreshSession(ctx, old.SessionToken)
	require.NoError(t, err)

	fs := faultstorage.NewFaultyStorage(st, &faultstorage.FaultSpec{
		Method: "ListSessionTokenHashesByFamily", NthCall: 1, Kind: faultstorage.KindPanic,
		Err: fmt.Errorf("injected panic"),
	})
	c.storage = fs
	require.NotPanics(t, func() { _, err = c.RefreshSession(ctx, old.SessionToken) })
	require.True(t, fs.Fired())
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrRefreshNotEvaluated), "a replayed token reached a verdict: %v", err)

	_, err = st.GetSession(ctx, fresh.SessionToken)
	assert.True(t, storage.IsSessionNotFound(err),
		"the rotated-to descendant must be revoked even though the hash listing panicked: %v", err)
}
