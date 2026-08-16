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

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

// TestCanonicalIP is #G20's detection_idea: assert multiple textual
// representations of the same source normalize to one canonical form.
func TestCanonicalIP(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"bare IPv4", "203.0.113.9", "203.0.113.9"},
		{"IPv4 with port", "203.0.113.9:5555", "203.0.113.9"},
		{"bracketed IPv6 with port", "[2001:db8::1]:5555", "2001:db8::1"},
		{"bare unbracketed IPv6, no port", "2001:db8::1", "2001:db8::1"},
		{"expanded IPv6 form compresses to the same canonical address", "2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"},
		{"non-IP host is returned unchanged", "not-an-ip", "not-an-ip"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, CanonicalIP(tc.in))
		})
	}
}

// TestRateLimit_CanonicalizesIPBeforeKeying is #G20: IsLoginRateLimited/
// RecordFailedLogin previously used the caller-supplied IP string as-is, so
// trivially different textual representations of the SAME source (a
// caller-supplied host:port vs. a bare IP, or two equivalent IPv6 forms) each
// got their own independent budget instead of sharing one — defeating the
// budget for any caller that varies its representation (or simply forgets to
// strip the port, as several HTTP handlers previously did independently and
// inconsistently).
func TestRateLimit_CanonicalizesIPBeforeKeying(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()

	// Reach the budget using the host:port form...
	for i := 0; i < LoginMaxAttempts; i++ {
		c.RecordFailedLogin(ctx, "203.0.113.9:5555")
	}
	// ...a bare-IP request from the SAME source (identical once canonicalized)
	// must already be blocked, not get a fresh budget under a different key.
	assert.True(t, c.IsLoginRateLimited(ctx, "203.0.113.9"),
		"a bare IP must share the same bucket as a host:port form of the identical address")

	// Two equivalent IPv6 textual forms must also share one bucket.
	c2, _ := newRateLimitCore(t)
	for i := 0; i < LoginMaxAttempts; i++ {
		c2.RecordFailedLogin(ctx, "2001:0db8:0000:0000:0000:0000:0000:0001")
	}
	assert.True(t, c2.IsLoginRateLimited(ctx, "2001:db8::1"),
		"an alternate IPv6 textual form of the same address must share the same bucket")
}

// TestRateLimit_SSOBegin_BlocksAtBudgetAndExpiresWithWindow is #G82: BeginSSO/
// BeginSAML previously had no rate limit at all, letting an unauthenticated
// flood grow the SSOLoginState table without bound.
func TestRateLimit_SSOBegin_BlocksAtBudgetAndExpiresWithWindow(t *testing.T) {
	c, setNow := newRateLimitCore(t)
	ctx := context.Background()
	base := c.now()

	for i := 0; i < SSOBeginMaxAttempts-1; i++ {
		c.RecordSSOBeginAttempt(ctx, "1.2.3.4")
	}
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "under budget is allowed")

	c.RecordSSOBeginAttempt(ctx, "1.2.3.4")
	assert.True(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "at the budget the IP is blocked")

	assert.False(t, c.IsSSOBeginRateLimited(ctx, "9.9.9.9"), "a different IP is unaffected")

	setNow(base.Add(SSOBeginWindow + time.Minute))
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "attempts age out of the window")
}

func TestRateLimit_SSOBegin_EmptyIPNeverLimited(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()
	for i := 0; i < SSOBeginMaxAttempts+5; i++ {
		c.RecordSSOBeginAttempt(ctx, "")
	}
	assert.False(t, c.IsSSOBeginRateLimited(ctx, ""), "an empty IP is never rate-limited")
}

// TestRateLimit_SSOBegin_SharesLoginAttemptTableButOwnBudget confirms the
// ssoRateLimitPrefix namespacing: an IP flooding the login endpoint doesn't
// also consume its SSO-begin budget, and vice versa — they're independent
// counters sharing one table (matching the existing password-reset prefix
// convention).
func TestRateLimit_SSOBegin_SharesLoginAttemptTableButOwnBudget(t *testing.T) {
	c, _ := newRateLimitCore(t)
	ctx := context.Background()

	for i := 0; i < LoginMaxAttempts; i++ {
		c.RecordFailedLogin(ctx, "1.2.3.4")
	}
	require.True(t, c.IsLoginRateLimited(ctx, "1.2.3.4"))
	assert.False(t, c.IsSSOBeginRateLimited(ctx, "1.2.3.4"), "login attempts must not consume the SSO-begin budget")
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
	removed, err := c.PruneLoginAttempts(ctx, time.Time{}, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(5), removed)

	n, err := c.storage.CountRecentLoginAttempts(ctx, "1.2.3.4", time.Time{})
	require.NoError(t, err)
	assert.Zero(t, n, "table is empty after pruning aged rows")
}

// TestPruneLoginAttempts_ClampsFutureBeforeToWindow is the CORE-RATE-003
// regression test at the core layer: a caller-supplied `before` LATER than
// now-LoginWindow (an attacker-controlled request body's far-future
// timestamp, e.g. "2099-01-01T00:00:00Z") must never widen the deletion
// window — the storage call underneath must always receive the clamped
// cutoff, not the caller's value.
func TestPruneLoginAttempts_ClampsFutureBeforeToWindow(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	maxCutoff := now.Add(-LoginWindow)
	attackerBefore := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	mockStore := new(MockStorage)
	// Expectation is set on the CLAMPED cutoff, not the attacker's `before` —
	// if the fix regresses to passing `before` straight through, this
	// expectation is never satisfied and testify panics on the unexpected call.
	mockStore.On("PruneLoginAttempts", mock.Anything, maxCutoff).Return(int64(3), nil)
	mockStore.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), attackerBefore, 1)
	require.NoError(t, err)
	assert.Equal(t, int64(3), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneLoginAttempts_NarrowerBeforeIsHonored confirms a caller CAN still
// narrow the deletion window below the default now-LoginWindow cutoff (a
// stricter, not wider, request) — only widening past the window is blocked.
func TestPruneLoginAttempts_NarrowerBeforeIsHonored(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	narrowerBefore := now.Add(-2 * LoginWindow)

	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, narrowerBefore).Return(int64(1), nil)
	mockStore.On("LogAuditEvent", mock.Anything, mock.Anything).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), narrowerBefore, 0)
	require.NoError(t, err)
	assert.Equal(t, int64(1), removed)
	mockStore.AssertExpectations(t)
}

// TestPruneLoginAttempts_AuditsActorRowCountAndCutoff proves the previously
// entirely-missing audit trail (CORE-RATE-003): a successful prune that
// actually removes rows emits a data.login_attempts_pruned event recording
// the acting principal, the row count, and the effective cutoff — mirroring
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords.
func TestPruneLoginAttempts_AuditsActorRowCountAndCutoff(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	maxCutoff := now.Add(-LoginWindow)

	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, maxCutoff).Return(int64(7), nil)

	var audited *models.AuditEvent
	mockStore.On("LogAuditEvent", mock.Anything, mock.MatchedBy(func(e *models.AuditEvent) bool {
		if e.EventType == "data.login_attempts_pruned" {
			audited = e
			return true
		}
		return false
	})).Return(nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	actorID := uint(42)
	removed, err := c.PruneLoginAttempts(context.Background(), time.Time{}, actorID)
	require.NoError(t, err)
	assert.Equal(t, int64(7), removed)

	require.NotNil(t, audited, "a data.login_attempts_pruned audit event must be written when rows are removed")
	require.NotNil(t, audited.UserID, "the acting principal is recorded")
	assert.Equal(t, actorID, *audited.UserID)
	assert.Contains(t, audited.Description, "7", "row count is recorded")
	assert.Contains(t, audited.Description, maxCutoff.UTC().Format(time.RFC3339), "effective cutoff is recorded")
}

// TestPruneLoginAttempts_NoAuditWhenNothingRemoved mirrors
// PurgeExpiredSoftDeletes/PurgeExpiredComplianceRecords: a prune that removes
// zero rows writes no audit event at all (avoids flooding the audit trail
// every maintenance-sweep tick when there's nothing to report).
func TestPruneLoginAttempts_NoAuditWhenNothingRemoved(t *testing.T) {
	now := time.Date(2026, 6, 12, 10, 0, 0, 0, time.UTC)
	mockStore := new(MockStorage)
	mockStore.On("PruneLoginAttempts", mock.Anything, mock.Anything).Return(int64(0), nil)

	c := &KeyorixCore{storage: mockStore, now: func() time.Time { return now }, passwordPolicy: DefaultPasswordPolicy()}
	removed, err := c.PruneLoginAttempts(context.Background(), time.Time{}, 5)
	require.NoError(t, err)
	assert.Zero(t, removed)
	mockStore.AssertNotCalled(t, "LogAuditEvent", mock.Anything, mock.Anything)
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
	removed, err := c.PruneLoginAttempts(ctx, time.Time{}, 0)
	require.NoError(t, err, "PruneLoginAttempts now succeeds against a real remote-storage upstream")
	assert.Equal(t, int64(LoginMaxAttempts+PasswordResetMaxAttempts), removed, "every aged login/password-reset attempt row was pruned upstream")
}
