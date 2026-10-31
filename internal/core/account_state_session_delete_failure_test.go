package core

// account_state_session_delete_failure_test.go -- ERRLOSS-TAILS-2 item 3.
//
// setAccountStateInTx deletes the sessions of a user moved into a login-blocking state
// (suspend, deactivate). That delete used to be `_ = tx.WithTransaction(...
// DeleteSessionsForUserExcept ...)`: a failure committed the suspension with the session
// rows still in storage and nothing logged or audited. AUTHZ-ORACLE-1 (#3815) gave it the
// PAT revocation's treatment (savepoint, one retry, a persistent failure reported after
// commit, never a rollback: INV-CORE-account-state-revocation-errors-reported) but tested
// only the PAT half. These are the session half.
//
// Effects are asserted from the DB (session rows, account_state, audit rows), not return
// values: SuspendUser returned nil before the fix too.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// A one-off fault on the session delete of a suspend is retried: the session rows are gone
// from storage and no failure is reported. Before the fix the suspension committed with the
// session row still there.
func TestSuspendUser_SessionDeleteTransientFault_IsRetriedAndDeleted(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, false)
		id := rw.seedUser(t, "sessdel", "", false)
		w.fs.Arm(&faultstorage.FaultSpec{
			Method: "DeleteSessionsForUserExcept", NthCall: 1, Kind: faultstorage.KindError,
			Err: errors.New("injected: one-off session delete failure"),
		})

		require.NoError(t, rw.c.SuspendUser(context.Background(), 0, id))

		assert.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")
		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountSuspended, after.AccountState)
		assert.Zero(t, rw.sessionCount(t, id), "the suspension committed with the session rows still in storage")
		assert.True(t, patRevokedInDB(t, rw, id), "the PAT revocation after the retried delete still runs")
		assert.Zero(t, rw.auditCount(t, EventSessionRevocationFailed), "no failure event when the retry succeeded")
	})
}

// A session delete that keeps failing, retry included, does not roll the suspension back
// (INV-CORE-account-state-revocation-errors-reported). It is reported: SECURITY log naming
// the delete, one EventSessionRevocationFailed, per-user auth-cache eviction. The leftover
// session row is refused while the account is suspended.
func TestSuspendUser_SessionDeletePersistentFailure_IsReportedAndSessionRefused(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		// newRevokeListWorld wires the log capture and the cache seams; the core is then
		// rebuilt over a store whose session delete always fails, inside the tx too.
		rw := newRevokeListWorld(t, w, false)
		var deleteCalls int
		rw.c = NewKeyorixCore(hooked(w.fs, &storeHooks{
			WrapTx: true,
			DeleteSessionsForUserExcept: func(_ storage.Storage, _ context.Context, _ uint, _ uint) error {
				deleteCalls++
				return errors.New("injected: session delete unavailable")
			},
		}))
		rw.c.SetTokenCacheInvalidator(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
		rw.c.SetTokenCacheClearer(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
		rw.c.SetUserTokenCacheEvictor(func(id uint) { rw.evictedUsers = append(rw.evictedUsers, id) })
		ctx := context.Background()

		id := rw.seedUser(t, "sessdelfail", "", false)
		const raw = "raw-session-token-sessdelfail"
		require.NoError(t, rw.db.Create(&models.Session{UserID: id, SessionToken: sha256Hex(raw), CreatedAt: time.Now()}).Error)
		_, _, err := rw.c.ValidateSessionToken(ctx, raw)
		require.NoError(t, err, "control: the seeded session must validate before the suspend, or the refusal below proves nothing")

		require.NoError(t, rw.c.SuspendUser(ctx, 0, id), "a failed session delete must not roll the suspension back")

		assert.GreaterOrEqual(t, deleteCalls, 2, "the delete must be retried once before it is given up on")
		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountSuspended, after.AccountState)
		assert.Equal(t, int64(2), rw.sessionCount(t, id), "the rows survive the failed delete; this is what is reported")
		assert.True(t, patRevokedInDB(t, rw, id), "the PAT revocation is independent of the failed session delete")
		assert.Equal(t, int64(1), rw.auditCount(t, EventSessionRevocationFailed))
		assert.Contains(t, rw.logs.String(), "SECURITY:")
		assert.Contains(t, rw.logs.String(), "delete sessions")
		assert.Contains(t, rw.evictedUsers, id, "every auth-cache entry of the user must be evicted when the delete failed")

		_, _, err = rw.c.ValidateSessionToken(ctx, raw)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "account is not active", "the surviving session must be refused by the account-state check")
	})
}

// patRevokedInDB reads the seeded PAT's revoked flag (kept local so this file also
// compiles on the pre-#3815 base for the red run).
func patRevokedInDB(t *testing.T, rw *revokeListWorld, id uint) bool {
	t.Helper()
	var p models.PersonalAccessToken
	require.NoError(t, rw.db.Where("user_id = ?", id).First(&p).Error)
	return p.Revoked
}
