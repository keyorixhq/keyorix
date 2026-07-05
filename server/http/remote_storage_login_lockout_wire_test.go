// remote_storage_login_lockout_wire_test.go — end-to-end regression coverage for
// #500: RemoteStorage.LockUserForUpdate (internal/storage/store/remote_users.go)
// is the exact call internal/core/login_lockout.go's checkLockAndClearLoginFailures
// makes to re-verify an account's lock state immediately before minting a session
// (its anti-TOCTOU recheck) under storage.type: remote. Two independent gaps used
// to defeat that recheck:
//
//  1. userToAPIResponse (server/http/handlers/users_handler.go) never put
//     failed_login_attempts/login_lockout_count/last_failed_login_at on the wire at
//     all — login_locked_until itself was already fixed separately (#496/#803), but
//     the other three lockout-accounting columns were not, so the recheck's own
//     "nothing to clear" fast path always saw a false all-zero snapshot.
//  2. LockUserForUpdate used to simply call GetUser, sharing its 5-minute response
//     cache (internal/storage/remote/client.go). A lock tripped by ANY caller since
//     that cache entry was populated — including this same client's own earlier
//     LockUserForUpdate call, or an unrelated admin "view user" GetUser call — went
//     completely unobserved for up to 5 minutes, silently defeating the recheck via
//     stale cache data rather than a missing wire field.
//
// Driven against a REAL server (NewRouter), not a hand-rolled mock — a mock that
// manually sets fields "correctly" can never catch a real field-name/shape
// mismatch (the same lesson #452/#496/#794's own e2e tests were built around).
package http

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newLockoutWireTestUpstream builds a real upstream server (NewRouter over an
// in-memory SQLite-backed core) plus an admin token, and seeds one real user.
func newLockoutWireTestUpstream(t *testing.T) (upstreamCore *core.KeyorixCore, srv *httptest.Server, token string, userID uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstreamCore = newTestCore(t)
	token = createTestToken(t, upstreamCore)

	cfg := &config.Config{Server: config.ServerConfig{HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"}}}
	upstreamRouter, err := NewRouter(cfg, upstreamCore)
	require.NoError(t, err)
	srv = httptest.NewServer(upstreamRouter)
	t.Cleanup(srv.Close)

	seeded, err := upstreamCore.CreateUser(context.Background(), &core.CreateUserRequest{
		Username: "e2e-lockout-wire", Email: "e2e-lockout-wire@example.com",
		Password: "Qr7#Kp2$Lm5@Vn9!", DisplayName: "Lockout Wire Test User",
	})
	require.NoError(t, err)
	return upstreamCore, srv, token, seeded.ID
}

// TestRemoteStorage_LoginLockoutWireFix_RealServerRoundTrip proves the wire-field
// half of the #500 fix end-to-end: a real server's response must carry the full
// login-lockout accounting state, and RemoteStorage.LockUserForUpdate — the exact
// call checkLockAndClearLoginFailures makes — must decode all of it, not just
// login_locked_until. Uses LockUserForUpdate throughout (never GetUser) since it is
// deliberately cache-bypassing (see the second test below); GetUser's own 5-minute
// cache is orthogonal to what this test asserts.
func TestRemoteStorage_LoginLockoutWireFix_RealServerRoundTrip(t *testing.T) {
	upstreamCore, srv, token, userID := newLockoutWireTestUpstream(t)
	ctx := context.Background()

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: token, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	// --- baseline: a freshly created user has no lockout state at all ---
	fresh, err := rs.LockUserForUpdate(ctx, userID)
	require.NoError(t, err)
	assert.Zero(t, fresh.FailedLoginAttempts)
	assert.Zero(t, fresh.LoginLockoutCount)
	assert.Nil(t, fresh.LastFailedLoginAt)
	assert.Nil(t, fresh.LoginLockedUntil)

	// --- simulate a concurrent burst of failed logins tripping the lock directly
	// against the upstream's own storage (exactly what recordFailedLogin does
	// server-side; this bypasses the wire entirely so the assertions below are only
	// about the read path this fix touches) ---
	lastFailed := time.Now().Add(-time.Second).UTC().Truncate(time.Second)
	lockedUntil := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, upstreamCore.Storage().UpdateLoginLockoutState(ctx, userID, 3, &lastFailed, &lockedUntil, 2))

	// --- the fix under test: LockUserForUpdate must decode the FULL
	// lockout-accounting state from the real response, not just login_locked_until ---
	locked, err := rs.LockUserForUpdate(ctx, userID)
	require.NoError(t, err, "LockUserForUpdate must not be misreported as a failure for a genuinely successful upstream response")

	require.NotNil(t, locked.LoginLockedUntil, "#500: login_locked_until must decode (this half was already fixed by #803)")
	assert.WithinDuration(t, lockedUntil, *locked.LoginLockedUntil, time.Second)
	assert.Equal(t, 3, locked.FailedLoginAttempts,
		"#500: failed_login_attempts must decode from the response, not silently zero")
	assert.Equal(t, 2, locked.LoginLockoutCount,
		"#500: login_lockout_count must decode from the response, not silently zero")
	require.NotNil(t, locked.LastFailedLoginAt,
		"#500: last_failed_login_at must decode from the response, not silently nil")
	assert.WithinDuration(t, lastFailed, *locked.LastFailedLoginAt, time.Second)

	// --- once the lock has genuinely expired (in the past), the server treats the
	// account as unlocked again and omits login_locked_until — the accounting
	// counters, however, are unconditional and must still round-trip ---
	pastLock := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, upstreamCore.Storage().UpdateLoginLockoutState(ctx, userID, 1, &lastFailed, &pastLock, 2))
	expired, err := rs.LockUserForUpdate(ctx, userID)
	require.NoError(t, err)
	assert.Nil(t, expired.LoginLockedUntil, "an expired lock must read as unlocked, matching userToAPIResponse's own behaviour")
	assert.Equal(t, 1, expired.FailedLoginAttempts, "#500: the accounting counters round-trip independently of the derived lock flag")
	assert.Equal(t, 2, expired.LoginLockoutCount)
}

// TestRemoteStorage_LockUserForUpdate_BypassesGetUserCache proves the second half
// of the #500 fix: LockUserForUpdate must always see the row's current state, even
// when an ordinary GetUser call for the SAME user was recently cached. Before this
// fix, LockUserForUpdate delegated straight to GetUser and so shared its 5-minute
// response cache (internal/storage/remote/client.go) — a lock tripped after that
// cache entry was populated would be invisible to the anti-TOCTOU recheck for up to
// 5 minutes, exactly the class of bug #500 describes (just rooted in cache
// staleness rather than a missing wire field).
func TestRemoteStorage_LockUserForUpdate_BypassesGetUserCache(t *testing.T) {
	upstreamCore, srv, token, userID := newLockoutWireTestUpstream(t)
	ctx := context.Background()

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL: srv.URL, APIKey: token, TimeoutSeconds: 5, RetryAttempts: 0, TLSVerify: true,
	})
	require.NoError(t, err)

	// Populate GetUser's cache with the account's UNLOCKED state — this is the same
	// client instance and the same cache key (GET:/api/v1/users/{id}) that
	// LockUserForUpdate used to share before this fix.
	unlocked, err := rs.GetUser(ctx, userID)
	require.NoError(t, err)
	require.Nil(t, unlocked.LoginLockedUntil)

	// Trip the lock directly against the upstream's own storage — simulating a
	// concurrent burst of failed logins committing via a path that does not go
	// through THIS client (e.g. another instance, or the upstream server's own
	// direct login processing).
	lockedUntil := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
	require.NoError(t, upstreamCore.Storage().UpdateLoginLockoutState(ctx, userID, 1, nil, &lockedUntil, 1))

	// The fix under test: LockUserForUpdate must see the fresh, locked state —
	// never the stale cache entry GetUser just populated above.
	relocked, err := rs.LockUserForUpdate(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, relocked.LoginLockedUntil,
		"#500: LockUserForUpdate must bypass GetUser's response cache — the anti-TOCTOU "+
			"recheck must never observe a lock that was tripped since the last cached GetUser read")
	assert.WithinDuration(t, lockedUntil, *relocked.LoginLockedUntil, time.Second)

	// Documents the (unchanged, deliberate) other half of this behaviour: an
	// ordinary GetUser call for the same path is still served from its own
	// 5-minute cache and so still reports the stale unlocked snapshot — this is
	// GetUser's existing, intentional performance trade-off, not a regression,
	// and is exactly why the security-sensitive recheck must use LockUserForUpdate
	// and not GetUser directly.
	stillCached, err := rs.GetUser(ctx, userID)
	require.NoError(t, err)
	assert.Nil(t, stillCached.LoginLockedUntil,
		"GetUser's cache is unchanged by this fix; only LockUserForUpdate bypasses it")
}
