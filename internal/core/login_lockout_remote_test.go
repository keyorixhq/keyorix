package core

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// apiOKUser writes a successful envelope response wrapping user, matching the format
// RemoteStorage.GetUser (and so LockUserForUpdate, which is just GetUser — see
// remote_users.go) expects.
func apiOKUser(t *testing.T, w http.ResponseWriter, user *models.User) {
	t.Helper()
	type resp struct {
		Success bool         `json:"success"`
		Data    *models.User `json:"data"`
	}
	require.NoError(t, json.NewEncoder(w).Encode(resp{Success: true, Data: user}))
}

// newRemoteLockoutCore builds a KeyorixCore backed by RemoteStorage against a real
// httptest server that only serves GET /api/v1/users/{id} (LockUserForUpdate's
// underlying call, per remote_users.go) — always returning `user` unchanged, since
// nothing this test does can ever actually persist anything server-side.
// UpdateLoginLockoutState never has a wire endpoint to call at all (#454): it always
// returns storage.ErrUnsupportedByBackend regardless of what the test server does.
func newRemoteLockoutCore(t *testing.T, user *models.User, policy LoginLockoutPolicy) *KeyorixCore {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiOKUser(t, w, user)
	}))
	t.Cleanup(srv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: "test-key", TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: false,
	})
	require.NoError(t, err)
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: rs, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	c.SetLoginLockoutPolicy(policy)
	return c
}

// TestLockout_RemoteStorageFailsOpenLoudlyOnce is the (#454) regression for the
// "passive accounting" half of the fix: under storage.type: remote,
// UpdateLoginLockoutState can never persist anything (the upstream wire format has no
// field for these columns), so recordFailedLogin/checkLockAndClearLoginFailures must
// (a) never panic or block a login over it, and (b) log the operator-visible warning
// exactly ONCE per process — mirroring #452's identical treatment of the per-IP rate
// limiter's RemoteStorage gap.
func TestLockout_RemoteStorageFailsOpenLoudlyOnce(t *testing.T) {
	// MaxAttempts=1 so a single recordFailedLogin call already tries to trip the lock,
	// forcing an immediate attempt to persist via UpdateLoginLockoutState.
	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 1, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	user := &models.User{ID: 42, Username: "bob", AccountState: AccountActive, IsActive: true}
	c := newRemoteLockoutCore(t, user, policy)
	ctx := context.Background()

	out := captureLog(t, func() {
		assert.NotPanics(t, func() { c.recordFailedLogin(ctx, user) })
	})
	assert.Contains(t, out, "login lockout accounting is INERT", "first call must log the operator warning")
	assert.Contains(t, out, "storage.type: remote")
	// Nothing was actually persisted, so the caller's in-memory struct must not be
	// mutated to falsely reflect a lock that was never recorded anywhere.
	assert.Nil(t, user.LoginLockedUntil, "must not claim a lock was applied when persistence failed")

	// The warning fires once per process, not once per call.
	out2 := captureLog(t, func() {
		for i := 0; i < 5; i++ {
			c.recordFailedLogin(ctx, user)
		}
	})
	assert.Empty(t, out2, "the warning must not repeat on subsequent calls")

	// checkLockAndClearLoginFailures must fail OPEN (allow the login) rather than
	// return its "unable to verify account lock state" fail-closed error — the backend
	// being permanently unable to clear the counters is not the same as a transient
	// storage error, and lockout is a backstop, not the primary auth boundary.
	lockedUser := &models.User{ID: 43, Username: "carol", AccountState: AccountActive, IsActive: true, FailedLoginAttempts: 2}
	c2 := newRemoteLockoutCore(t, lockedUser, policy)
	out3 := captureLog(t, func() {
		err := c2.checkLockAndClearLoginFailures(ctx, lockedUser)
		assert.NoError(t, err, "must not block login just because lockout accounting can't be persisted")
	})
	assert.Contains(t, out3, "login lockout accounting is INERT")
}

// TestUnlockUser_RemoteStorageFailsOpenLoudly is the (#484) regression for the admin
// UnlockUser path: it clears the identical four lockout-accounting columns that
// recordFailedLogin/checkLockAndClearLoginFailures clear automatically on a successful
// login, via the SAME UpdateLoginLockoutState primitive #454 already established for
// them — so it must get the identical fail-OPEN-but-loud treatment under storage.type:
// remote (log the operator warning once, return no error to the admin), not a hard
// failure: this is still passive lockout accounting, not an explicit security
// directive like account_state, and the worst case of the write silently no-op'ing is
// merely that the lock expires on its own cooldown instead of clearing early.
func TestUnlockUser_RemoteStorageFailsOpenLoudly(t *testing.T) {
	policy := LoginLockoutPolicy{Enabled: true, MaxAttempts: 3, Window: 15 * time.Minute, BaseCooldown: time.Minute, MaxCooldown: time.Hour}
	user := &models.User{ID: 44, Username: "dave", AccountState: AccountActive, IsActive: true, FailedLoginAttempts: 2, LoginLockoutCount: 1}
	c := newRemoteLockoutCore(t, user, policy)
	ctx := context.Background()

	out := captureLog(t, func() {
		err := c.UnlockUser(ctx, 1, 44)
		assert.NoError(t, err, "an admin unlock must not fail just because lockout accounting can't be persisted")
	})
	assert.Contains(t, out, "login lockout accounting is INERT")

	// The warning fires once per process; a second unlock attempt logs nothing further.
	out2 := captureLog(t, func() {
		assert.NoError(t, c.UnlockUser(ctx, 1, 44))
	})
	assert.Empty(t, out2, "the warning must not repeat on subsequent calls")
}
