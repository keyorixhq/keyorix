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

// apiOKUser writes a successful envelope response wrapping user, matching the REAL
// wire shape server/http/handlers/users_handler.go's userToAPIResponse produces
// (snake_case keys) — not a raw models.User marshal. RemoteStorage.GetUser (and so
// LockUserForUpdate, which is just GetUser — see remote_users.go) decodes exactly
// this shape (#496); a raw-model mock would silently paper over the same
// request/response field-name mismatch #496 fixed, since both sides would share the
// identical (wrong) assumption.
//
// #500: failed_login_attempts/login_lockout_count/last_failed_login_at are now also
// part of that real shape (alongside the pre-existing login_locked_until), so this
// mock includes them unconditionally too — omitting them here would silently
// reintroduce the exact stale-mock blind spot #496's own fix was written to avoid.
func apiOKUser(t *testing.T, w http.ResponseWriter, user *models.User) {
	t.Helper()
	data := map[string]interface{}{
		"id":                    user.ID,
		"username":              user.Username,
		"email":                 user.Email,
		"display_name":          user.DisplayName,
		"active":                user.IsActive,
		"account_state":         user.AccountState,
		"created_at":            user.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":            user.UpdatedAt.UTC().Format(time.RFC3339),
		"last_login_at":         nil,
		"deleted_at":            nil,
		"failed_login_attempts": user.FailedLoginAttempts,
		"login_lockout_count":   user.LoginLockoutCount,
		"last_failed_login_at":  nil,
	}
	if user.LastLoginAt != nil {
		data["last_login_at"] = user.LastLoginAt.UTC().Format(time.RFC3339)
	}
	if user.LoginLockedUntil != nil {
		data["login_locked_until"] = user.LoginLockedUntil.UTC().Format(time.RFC3339)
	}
	if user.LastFailedLoginAt != nil {
		data["last_failed_login_at"] = user.LastFailedLoginAt.UTC().Format(time.RFC3339)
	}
	type resp struct {
		Success bool        `json:"success"`
		Data    interface{} `json:"data"`
	}
	require.NoError(t, json.NewEncoder(w).Encode(resp{Success: true, Data: data}))
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
	//
	// #500 (this used to be a separately-filed gap, discovered fixing #496): before
	// this fix, this path did NOT log the INERT warning against a real remote server.
	// checkLockAndClearLoginFailures's (login_lockout.go) "nothing to clear" fast path
	// is keyed on the freshly-fetched u.FailedLoginAttempts/LoginLockedUntil/
	// LoginLockoutCount; when userToAPIResponse (server/http/handlers/users_handler.go)
	// never put failed_login_attempts/login_lockout_count on the wire at all, that fast
	// path always observed a false all-zero snapshot under storage.type: remote, so it
	// always took the early return — UpdateLoginLockoutState was never even attempted
	// and the warning never fired, silently leaving any real stale accounting
	// unreported (though, since #454, still safely unpersisted either way — this was an
	// observability gap in the "loudly" half of "fail open loudly", not a security one).
	// Now that those fields are on the wire, a user with genuine unreset accounting
	// (FailedLoginAttempts: 2 below) is no longer mistaken for "nothing to clear": the
	// fast path is skipped, UpdateLoginLockoutState is attempted, fails unsupported, and
	// the operator warning correctly fires from this call path too.
	lockedUser := &models.User{ID: 43, Username: "carol", AccountState: AccountActive, IsActive: true, FailedLoginAttempts: 2}
	c2 := newRemoteLockoutCore(t, lockedUser, policy)
	out3 := captureLog(t, func() {
		err := c2.checkLockAndClearLoginFailures(ctx, lockedUser)
		assert.NoError(t, err, "must not block login just because lockout accounting can't be persisted")
	})
	assert.Contains(t, out3, "login lockout accounting is INERT",
		"#500: real unreset accounting (FailedLoginAttempts>0) must no longer be mistaken "+
			"for 'nothing to clear' now that these fields are on the wire")
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
