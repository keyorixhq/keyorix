package core

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func newRateLimitCore(t *testing.T) (*KeyorixCore, func(time.Time)) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.LoginAttempt{}))
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: store.NewLocalStorage(db), now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	setNow := func(t time.Time) { c.now = func() time.Time { return t } }
	return c, setNow
}

func TestRateLimit_BlocksAtBudgetAndExpiresWithWindow(t *testing.T) {
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()

	// Below the budget: allowed.
	for i := 0; i < LoginMaxAttempts-1; i++ {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "under budget is allowed")

	// Reaching the budget: blocked.
	c.RecordFailedLogin(ctx, "1.2.3.4")
	assert.True(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "at the budget the IP is blocked")

	// A different IP is unaffected.
	assert.False(t, c.IsLoginRateLimited(ctx, "9.9.9.9"))

	// After the window elapses, the old attempts no longer count.
	setNow(base.Add(LoginWindow + time.Minute))
	assert.False(t, c.IsLoginRateLimited(ctx, "1.2.3.4"), "attempts age out of the window")
}

func TestRateLimit_EmptyIPNeverLimited(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	for i := 0; i < LoginMaxAttempts+5; i++ {
		c.RecordFailedLogin(ctx, "")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, ""), "an empty IP is never rate-limited")
}

func TestRateLimit_PruneRemovesAgedRows(t *testing.T) {
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()
	for i := 0; i < 5; i++ {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	// Move past the window and prune — aged rows are removed.
	setNow(base.Add(LoginWindow + time.Minute))
	removed, err := c.PruneLoginAttempts(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), removed)

	n, err := c.storage.CountRecentLoginAttempts(ctx, "1.2.3.4", time.Time{})
	require.NoError(t, err)
	assert.Zero(t, n, "table is empty after pruning aged rows")
}

// newRemoteRateLimitCore builds a KeyorixCore backed by RemoteStorage — the
// backend a server runs when configured with storage.type: remote — with no
// HTTP server behind it: CountRecentLoginAttempts/RecordLoginAttempt never make
// a network call at all, they return store.ErrRemoteUnsupported unconditionally
// (see internal/storage/store/remote_login_attempts.go).
func newRemoteRateLimitCore(t *testing.T) *KeyorixCore {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        "https://unused.example",
		APIKey:         "test-key",
		TimeoutSeconds: 30,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	return &KeyorixCore{storage: rs, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
}

// TestRateLimit_RemoteStorageFailsOpenSilentlyOnlyOnce (#452) proves the fix: a
// server running storage.type: remote has NO working login-attempt counter
// (RemoteStorage.CountRecentLoginAttempts always errors, per ADR-040 — see
// remote_login_attempts.go), so IsLoginRateLimited/IsPasswordResetRateLimited
// still fail open on every call (unavoidable without a real proxy — see #452's
// design note there) — but the operator-visible warning about that gap fires
// exactly ONCE per process, not once per request/login attempt.
func TestRateLimit_RemoteStorageFailsOpenSilentlyOnlyOnce(t *testing.T) {
	c := newRemoteRateLimitCore(t)
	ctx := context.Background()

	// The very first call already fails open (never blocks a login) AND emits
	// the one-time warning.
	var limited bool
	out := captureLog(t, func() {
		limited = c.IsLoginRateLimited(ctx, "203.0.113.5")
	})
	assert.False(t, limited, "fails open: an unsupported-backend error must never block login")
	assert.Contains(t, out, "rate limiting is INERT", "first call must log the operator warning")
	assert.Contains(t, out, "storage.type: remote")

	// Every subsequent call (login rate limit AND password-reset rate limit,
	// which share the same warnRateLimitUnsupportedOnce) keeps failing open, but
	// must NOT log the warning again — otherwise a brute-force flood would spam
	// the log once per request, defeating the point of a "loud, ONE-TIME" signal.
	out2 := captureLog(t, func() {
		for i := 0; i < 25; i++ {
			assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.5"))
		}
		assert.False(t, c.IsPasswordResetRateLimited(ctx, "203.0.113.5"))
	})
	assert.Empty(t, out2, "the warning must not repeat on subsequent calls")

	// RecordFailedLogin/PruneLoginAttempts are best-effort against the same
	// always-erroring backend and must never panic or block the caller.
	assert.NotPanics(t, func() { c.RecordFailedLogin(ctx, "203.0.113.5") })
	_, err := c.PruneLoginAttempts(ctx)
	assert.Error(t, err, "PruneLoginAttempts surfaces the storage error (it is not a fail-open path)")
	assert.True(t, isUnsupportedByBackend(err))
}
