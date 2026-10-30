package core

// account_state_pat_failure_test.go -- AUTHZ-ORACLE-1 item 3.
//
// setAccountStateInTx (suspend, deactivate, require-password-reset, ...) lists the
// user's PATs to evict their auth-cache entries and, for a login-blocking state,
// revokes them. Both errors used to be discarded: `pats, _ := tx.ListPersonalAccessTokensByUser`
// and `_ = tx.WithTransaction(... RevokeAllPersonalAccessTokensForUser ...)`. A failed
// listing evicted no PAT entry and reported nothing; a failed revocation committed the
// suspension with the PATs still live in storage (usable again the moment the account
// is reactivated), again with nothing logged or audited.
//
// Now both get the session listing's treatment (#3777, ERRLOSS-REVOKE-1): a savepoint,
// one retry, and a persistent failure carried to the post-commit step, which evicts
// every cache entry of the user, logs a SECURITY line and audits
// EventSessionRevocationFailed. The suspension itself is never rolled back.
//
// Effects are asserted, not return values: every one of these paths returned nil
// before the fix too.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rw *revokeListWorld) patRevoked(t *testing.T, id uint) bool {
	t.Helper()
	var p models.PersonalAccessToken
	require.NoError(t, rw.db.Where("user_id = ?", id).First(&p).Error)
	return p.Revoked
}

// A one-off fault on the PAT revocation of a suspend is retried: the PAT ends up
// revoked in storage and its hash evicted. Before the fix the suspension committed
// with the PAT still live.
func TestSuspendUser_PATRevocationTransientFault_IsRetriedAndRevoked(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, false)
		id := rw.seedUser(t, "patrevoke", "", false)
		w.fs.Arm(&faultstorage.FaultSpec{
			Method: "RevokeAllPersonalAccessTokensForUser", NthCall: 1, Kind: faultstorage.KindError,
			Err: errors.New("injected: one-off PAT revocation failure"),
		})

		require.NoError(t, rw.c.SuspendUser(context.Background(), 0, id))

		assert.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")
		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountSuspended, after.AccountState)
		assert.True(t, rw.patRevoked(t, id), "the suspension committed with the PAT still live in storage")
		assert.Contains(t, rw.evictedHash, "pat-patrevoke")
		assert.Zero(t, rw.auditCount(t, EventSessionRevocationFailed), "no failure event when the retry succeeded")
	})
}

// A one-off fault on the PAT listing of a restriction (password_reset_required: the
// PAT is not revoked, only its cache entry evicted) is retried, so the PAT's cache
// entry is still evicted. Before the fix it was silently skipped and a cached PAT kept
// its pre-restriction identity for up to the auth-cache TTL.
func TestRequirePasswordReset_PATListingTransientFault_IsRetriedAndEvicted(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, false)
		id := rw.seedUser(t, "patlist", "", false)
		w.fs.Arm(&faultstorage.FaultSpec{
			Method: "ListPersonalAccessTokensByUser", NthCall: 1, Kind: faultstorage.KindError,
			Err: errors.New("injected: one-off PAT listing failure"),
		})

		require.NoError(t, rw.c.RequirePasswordReset(context.Background(), 0, id))

		assert.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")
		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountPasswordResetRequired, after.AccountState)
		assert.Contains(t, rw.evictedHash, "pat-patlist", "the PAT's cache entry was not evicted")
		assert.Empty(t, rw.evictedUsers, "no per-user fallback when the retry succeeded")
	})
}
