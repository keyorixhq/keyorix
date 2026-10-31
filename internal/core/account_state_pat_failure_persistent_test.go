package core

// Persistent-failure half of account_state_pat_failure_test.go (AUTHZ-ORACLE-1 item 3):
// a PAT listing or revocation that fails on every call, retry included, is reported
// and never rolls the state change back. Kept apart because it needs the PAT hooks
// added to storagetest.StoreHooks with the fix.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// newPATFailureWorld is revokeListWorld's core rebuilt over hooks that make the PAT
// listing and/or the PAT revocation fail on every call, inside the transaction too.
func newPATFailureWorld(t *testing.T, w *txClosureWorld, failList, failRevoke bool) *revokeListWorld {
	t.Helper()
	rw := &revokeListWorld{txClosureWorld: w, logs: &bytes.Buffer{}}
	h := &storeHooks{WrapTx: true}
	if failList {
		h.ListPersonalAccessTokensByUser = func(_ storage.Storage, _ context.Context, _ uint) ([]*models.PersonalAccessToken, error) {
			return nil, errors.New("injected: PAT listing unavailable")
		}
	}
	if failRevoke {
		h.RevokeAllPersonalAccessTokensForUser = func(_ storage.Storage, _ context.Context, _ uint) ([]string, error) {
			return nil, errors.New("injected: PAT revocation unavailable")
		}
	}
	rw.c = NewKeyorixCore(hooked(w.fs, h))
	rw.c.SetTokenCacheInvalidator(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
	rw.c.SetTokenCacheClearer(func(hash string) { rw.evictedHash = append(rw.evictedHash, hash) })
	rw.c.SetUserTokenCacheEvictor(func(id uint) { rw.evictedUsers = append(rw.evictedUsers, id) })
	log.SetOutput(rw.logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return rw
}

// A PAT revocation that keeps failing does not roll the suspension back, and is
// reported: SECURITY log, EventSessionRevocationFailed, per-user cache eviction.
func TestSuspendUser_PATRevocationPersistentFailure_IsReported(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newPATFailureWorld(t, w, false, true)
		id := rw.seedUser(t, "patrevokefail", "", false)

		require.NoError(t, rw.c.SuspendUser(context.Background(), 0, id),
			"a failed PAT revocation must not roll the suspension back")

		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountSuspended, after.AccountState)
		assert.Zero(t, rw.sessionCount(t, id), "the sessions are still deleted")
		assert.Equal(t, int64(1), rw.auditCount(t, EventSessionRevocationFailed))
		assert.Contains(t, rw.logs.String(), "SECURITY:")
		assert.Contains(t, rw.logs.String(), "could not revoke the sessions/personal access tokens")
		assert.Contains(t, rw.evictedUsers, id)
	})
}

// A PAT listing that keeps failing is reported the way a failed session listing is.
func TestRequirePasswordReset_PATListingPersistentFailure_IsReported(t *testing.T) {
	txClosureBackends(t, func(t *testing.T, w *txClosureWorld) {
		rw := newPATFailureWorld(t, w, true, false)
		id := rw.seedUser(t, "patlistfail", "", false)

		require.NoError(t, rw.c.RequirePasswordReset(context.Background(), 0, id))

		var after models.User
		require.NoError(t, rw.db.First(&after, id).Error)
		assert.Equal(t, AccountPasswordResetRequired, after.AccountState)
		assert.Equal(t, int64(1), rw.auditCount(t, EventSessionRevocationFailed))
		assert.Contains(t, rw.evictedUsers, id, "every auth-cache entry of the user must be evicted when the PAT list is unavailable")

		// AUTHZ-ORACLE-TAILS-1 item 4: the text names the personal access tokens, not the
		// sessions (the PAT listing used to join the session listing's error).
		wantLog := fmt.Sprintf("could not list the personal access tokens of user %d", id)
		assert.Contains(t, rw.logs.String(), wantLog)
		assert.Contains(t, rw.logs.String(), "injected: PAT listing unavailable", "the cause is logged")
		assert.NotContains(t, rw.logs.String(), "could not list the sessions", "the session listing did not fail")

		var ev models.AuditEvent
		require.NoError(t, rw.db.Where("event_type = ?", EventSessionRevocationFailed).First(&ev).Error)
		assert.Contains(t, ev.Description, wantLog+" to evict them from the auth cache")
		assert.Contains(t, ev.Description, "injected: PAT listing unavailable")
		assert.NotContains(t, ev.Description, "could not list the sessions", "the audit row must not blame the sessions")
	})
}
