package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
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

// fakeUpstreamLoginAttempts is a minimal, in-memory stand-in for the real
// server-side login-attempts proxy (server/http/handlers/login_attempts_proxy.go,
// registered in server/http/router.go under /api/v1/system/login-attempts).
// internal/core cannot import server/http (server/http imports internal/core —
// that would be a package cycle), so this hand-rolls the identical wire contract,
// matching the existing convention internal/storage/store/remote_storage_test.go
// already uses for testing RemoteStorage against a synthetic server. The
// production-router version of this same scenario is
// TestRemoteStorageLoginRateLimit_ThrottlesAcrossRealServer in server/http, which
// exercises the ACTUAL handler code, not this stand-in.
type fakeUpstreamLoginAttempts struct {
	mu   sync.Mutex
	rows []struct {
		ip string
		at time.Time
	}
}

func (f *fakeUpstreamLoginAttempts) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/system/login-attempts/count", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		var n int64
		for _, row := range f.rows {
			if row.ip == ip && row.at.After(since) {
				n++
			}
		}
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"data":{"count":%d}}`, n)
	})
	mux.HandleFunc("/api/v1/system/login-attempts", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IP string    `json:"ip"`
			At time.Time `json:"at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.rows = append(f.rows, struct {
			ip string
			at time.Time
		}{ip: body.IP, at: body.At})
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"data":{"recorded":true}}`))
	})
	mux.HandleFunc("/api/v1/system/login-attempts/prune", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Before time.Time `json:"before"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		kept := f.rows[:0]
		var deleted int64
		for _, row := range f.rows {
			if row.at.Before(body.Before) {
				deleted++
				continue
			}
			kept = append(kept, row)
		}
		f.rows = kept
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"success":true,"data":{"deleted":%d}}`, deleted)
	})
	return httptest.NewServer(mux)
}

// newRemoteRateLimitCoreAgainst builds a KeyorixCore backed by RemoteStorage — the
// backend a server runs when configured with storage.type: remote — pointed at a
// real (test) HTTP server, so RecordLoginAttempt/CountRecentLoginAttempts genuinely
// round-trip over HTTP rather than being stubbed out.
func newRemoteRateLimitCoreAgainst(t *testing.T, baseURL string) (*KeyorixCore, func(time.Time)) {
	t.Helper()
	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        baseURL,
		APIKey:         "test-key",
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	c := &KeyorixCore{storage: rs, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	setNow := func(t time.Time) { c.now = func() time.Time { return t } }
	return c, setNow
}

// TestRateLimit_RemoteStorageGenuinelyThrottles (#452 follow-up) proves the fix: a
// server running storage.type: remote now has a REAL, working per-IP login-attempt
// counter — RecordLoginAttempt/CountRecentLoginAttempts genuinely persist to and
// query the upstream server over HTTP (see remote_login_attempts.go) — instead of
// silently failing open for the whole life of the process. Below the budget stays
// allowed, reaching the budget blocks, a different IP is unaffected, and the window
// still expires old attempts: the exact same behavior TestRateLimit_
// BlocksAtBudgetAndExpiresWithWindow already proves for LocalStorage.
func TestRateLimit_RemoteStorageGenuinelyThrottles(t *testing.T) {
	upstream := &fakeUpstreamLoginAttempts{}
	srv := upstream.server(t)
	defer srv.Close()

	c, setNow := newRemoteRateLimitCoreAgainst(t, srv.URL)
	ctx := context.Background()
	base := c.now()

	// Below the budget: allowed.
	for i := 0; i < LoginMaxAttempts-1; i++ {
		c.RecordFailedLogin(ctx, "203.0.113.5")
	}
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.5"), "under budget is allowed under storage.type: remote")

	// Reaching the budget: blocked.
	c.RecordFailedLogin(ctx, "203.0.113.5")
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.5"), "at the budget the IP is blocked under storage.type: remote too")

	// A different IP is unaffected.
	assert.False(t, c.IsLoginRateLimited(ctx, "9.9.9.9"))

	// Password-reset rate limiting shares the identical mechanism (a distinct
	// key prefix over the same counter) and is likewise genuinely throttled now.
	for i := 0; i < PasswordResetMaxAttempts; i++ {
		c.RecordPasswordResetAttempt(ctx, "198.51.100.9")
	}
	assert.True(t, c.IsPasswordResetRateLimited(ctx, "198.51.100.9"), "password-reset mail-bombing is now throttled under storage.type: remote")

	// After the window elapses, the old attempts no longer count — matching
	// LocalStorage's identical behavior in TestRateLimit_BlocksAtBudgetAndExpiresWithWindow.
	setNow(base.Add(LoginWindow + time.Minute))
	assert.False(t, c.IsLoginRateLimited(ctx, "203.0.113.5"), "attempts age out of the window under storage.type: remote too")

	// PruneLoginAttempts also genuinely round-trips (used by the maintenance sweep)
	// and actually removes the now-aged rows upstream (both the login-attempt rows
	// for 203.0.113.5 and the password-reset-prefixed rows for 198.51.100.9 — every
	// row recorded at `base`, now past both windows).
	removed, err := c.PruneLoginAttempts(ctx)
	require.NoError(t, err, "PruneLoginAttempts now succeeds against a real remote-storage upstream")
	assert.Equal(t, int64(LoginMaxAttempts+PasswordResetMaxAttempts), removed, "every aged login/password-reset attempt row was pruned upstream")
}
