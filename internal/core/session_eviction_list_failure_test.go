package core

// session_eviction_list_failure_test.go -- ERRLOSS-REVOKE-1.
//
// Every revocation path lists the user's session-token hashes (the auth-cache keys) before
// its write and evicts them after commit. The listing's error used to be discarded
// (`hashes, _ := ...`): a read failure meant no eviction, no log line and no audit row,
// while the revoked session kept authenticating for up to validTokenTTL.
//
// One test per entry path (password change, suspend, SCIM deactivate, delete user). The
// effect is asserted, not the return value: a swallowed listing failure returns nil at
// every layer, so each test checks that the primary operation took effect AND that the
// failure was audited, logged and followed by a per-user cache eviction. The listing is
// made to fail on every call (a hook over faultstorage: a FaultSpec fires once, and the
// helper retries once), including on the transaction handle (WrapTx) for the suspend
// path, which reads inside its transaction.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/faultstorage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// revokeListWorld is a txClosureWorld whose core can be rebuilt over a store whose
// ListSessionTokenHashesForUser always fails, with the auth-cache seams recorded.
type revokeListWorld struct {
	*txClosureWorld
	c            *KeyorixCore
	listCalls    int
	evictedHash  []string
	evictedUsers []uint
	logs         *bytes.Buffer
}

func newRevokeListWorld(t *testing.T, w *txClosureWorld, failListing bool) *revokeListWorld {
	t.Helper()
	rw := &revokeListWorld{txClosureWorld: w, logs: &bytes.Buffer{}}
	h := &storeHooks{WrapTx: true}
	h.ListSessionTokenHashesForUser = func(next storage.Storage, ctx context.Context, id uint) ([]string, error) {
		rw.listCalls++
		if failListing {
			return nil, errors.New("injected: session listing unavailable")
		}
		return next.ListSessionTokenHashesForUser(ctx, id)
	}
	rw.c = NewKeyorixCore(hooked(w.fs, h))
	rw.c.SetTokenCacheInvalidator(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
	rw.c.SetTokenCacheClearer(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
	rw.c.SetUserTokenCacheEvictor(func(id uint) { rw.evictedUsers = append(rw.evictedUsers, id) })
	log.SetOutput(rw.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return rw
}

// seedUser creates an active user with one session and one PAT (token "sess-<name>").
func (rw *revokeListWorld) seedUser(t *testing.T, name, externalID string, withPassword bool) uint {
	t.Helper()
	u := &models.User{Username: name, UsernameFolded: name, Email: name + "@example.com", EmailFolded: name + "@example.com",
		IsActive: true, AccountState: AccountActive, ExternalID: externalID}
	if withPassword {
		hash, err := bcrypt.GenerateFromPassword([]byte(curPwOld), int(bcryptCost.Load()))
		require.NoError(t, err)
		u.PasswordHash = string(hash)
	}
	require.NoError(t, rw.db.Create(u).Error)
	require.NoError(t, rw.db.Create(&models.Session{UserID: u.ID, SessionToken: "sess-" + name, CreatedAt: time.Now()}).Error)
	require.NoError(t, rw.db.Create(&models.PersonalAccessToken{UserID: u.ID, Name: "pat-" + name, TokenHash: "pat-" + name}).Error)
	return u.ID
}

func (rw *revokeListWorld) sessionCount(t *testing.T, id uint) int64 {
	t.Helper()
	var n int64
	require.NoError(t, rw.db.Model(&models.Session{}).Where("user_id = ?", id).Count(&n).Error)
	return n
}

// requireListFailureHandled asserts the three signals the silent discard never gave.
func (rw *revokeListWorld) requireListFailureHandled(t *testing.T, id uint) {
	t.Helper()
	assert.GreaterOrEqual(t, rw.listCalls, 2, "the listing must be retried once before it is given up on")
	assert.Equal(t, int64(1), rw.auditCount(t, EventSessionRevocationFailed),
		"the failed listing must write exactly one %s event", EventSessionRevocationFailed)
	assert.Contains(t, rw.logs.String(), "SECURITY:", "a SECURITY: line must be logged")
	assert.Contains(t, rw.logs.String(), fmt.Sprintf("could not list the sessions of user %d", id))
	assert.Contains(t, rw.evictedUsers, id, "every auth-cache entry of the user must be evicted when the hash list is unavailable")
}

func TestSessionListFailure_ChangePassword_StillChangesAuditsAndEvictsUser(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, true)
		id := rw.seedUser(t, "pwchange", "", true)

		require.NoError(t, rw.c.ChangePassword(context.Background(), id, curPwOld, curPwNew, ""),
			"a failed session listing must not fail the password change")

		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.NoError(t, bcrypt.CompareHashAndPassword([]byte(after.PasswordHash), []byte(curPwNew)), "the new password must be stored")
		assert.Zero(t, rw.sessionCount(t, id), "the DB-side session purge still happens")
		rw.requireListFailureHandled(t, id)
	})
}

func TestSessionListFailure_SuspendUser_StillSuspendsAuditsAndEvictsUser(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, true)
		id := rw.seedUser(t, "suspendee", "", false)

		require.NoError(t, rw.c.SuspendUser(context.Background(), 0, id),
			"a failed session listing inside the transaction must not roll the suspension back")

		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountSuspended, after.AccountState, "the suspension must have committed")
		assert.Zero(t, rw.sessionCount(t, id), "the sessions are still deleted")
		rw.requireListFailureHandled(t, id)
	})
}

func TestSessionListFailure_DeprovisionSCIMUser_StillDeprovisionsAuditsAndEvictsUser(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, true)
		id := rw.seedUser(t, "scimuser", "ext-scim-1", false)

		require.NoError(t, rw.c.DeprovisionSCIMUser(context.Background(), 0, id),
			"a failed session listing must not fail the SCIM deprovision")

		var after models.User
		require.NoError(t, rw.db.Unscoped().First(&after, id).Error)
		assert.False(t, after.IsActive, "the user must be deactivated")
		assert.Zero(t, rw.sessionCount(t, id), "the sessions are still deleted")
		rw.requireListFailureHandled(t, id)
	})
}

func TestSessionListFailure_DeleteUser_StillDeletesAuditsAndEvictsUser(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, true)
		id := rw.seedUser(t, "deletee", "", false)

		require.NoError(t, rw.c.DeleteUser(context.Background(), 0, id),
			"a failed session listing must not fail the delete")

		assert.Zero(t, rw.sessionCount(t, id), "the sessions are still deleted")
		rw.requireListFailureHandled(t, id)
	})
}

// A listing that fails once and then works (a transient fault) is retried, so the exact
// hashes are evicted and no failure is reported -- on a path that lists outside a
// transaction (password change) and one that lists inside it (suspend).
func TestSessionListFailure_TransientFault_IsRetriedWithoutAnAlarm(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, rw *revokeListWorld, id uint) error
		pw   bool
	}{
		{"change_password", func(t *testing.T, rw *revokeListWorld, id uint) error {
			return rw.c.ChangePassword(context.Background(), id, curPwOld, curPwNew, "")
		}, true},
		{"suspend", func(t *testing.T, rw *revokeListWorld, id uint) error {
			return rw.c.SuspendUser(context.Background(), 0, id)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
				rw := newRevokeListWorld(t, w, false)
				id := rw.seedUser(t, "transient", "", tc.pw)
				w.fs.Arm(&faultstorage.FaultSpec{
					Method: "ListSessionTokenHashesForUser", NthCall: 1, Kind: faultstorage.KindError,
					Err: errors.New("injected: one-off listing failure"),
				})

				require.NoError(t, tc.run(t, rw, id))

				assert.True(t, w.fs.Fired(), "the armed fault must have fired, or this test proves nothing")
				assert.Contains(t, rw.evictedHash, "sess-transient", "the retried listing must still evict the exact session hash")
				assert.Empty(t, rw.evictedUsers, "no per-user fallback when the retry succeeded")
				assert.Zero(t, rw.auditCount(t, EventSessionRevocationFailed), "no failure event when the retry succeeded")
				assert.NotContains(t, rw.logs.String(), "could not list the sessions")
			})
		})
	}
}

// Calibration: with no fault, nothing is reported and the exact hash is evicted.
func TestSessionListFailure_NoFault_ReportsNothing(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newRevokeListWorld(t, w, false)
		id := rw.seedUser(t, "healthy", "", false)
		require.NoError(t, rw.c.SuspendUser(context.Background(), 0, id))
		assert.Contains(t, rw.evictedHash, "sess-healthy")
		assert.Empty(t, rw.evictedUsers)
		assert.Zero(t, rw.auditCount(t, EventSessionRevocationFailed))
	})
}
