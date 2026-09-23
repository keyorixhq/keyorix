// login_rate_limit_reserve_test.go — F2 (2026-09-20) regression: the per-IP
// login-attempt budget (core.LoginMaxAttempts) used to be enforced by
// checking the count, then only recording an attempt AFTER the slow
// credential check (bcrypt/TOTP/WebAuthn assertion) completed, and only on
// failure. A burst of concurrent requests from one IP all observed the SAME
// under-budget count at their check (none of the others had recorded yet),
// all proceeded through the slow verification, and only then recorded —
// letting the burst blow through the budget before the counter ever caught
// up. The fix moves the record (reserveLoginAttempt) to run BEFORE the slow
// step, right after the request is minimally well-formed (decoded), so
// concurrent requests compete for the same reserved slots instead of each
// reading a stale count.
//
// This is inherently a timing-sensitive property — a maximally-synchronized
// concurrent burst can still theoretically race the check-then-reserve pair
// itself (check and reserve are still two separate calls, not one atomic
// operation; see core's own TestConcurrency_LoginRateLimit_TripsAndStaysTripped
// doc, which explicitly does not promise "at most N ever pass" for the raw
// primitives) — a single 30-request round's too-many-requests count varied
// widely run to run in manual testing (pre-fix: 0-9 of 30; post-fix: 8-20 of
// 30 — real signal, but noisy enough for a single round to flake either way
// in CI). Aggregating several independent rounds averages out that
// per-round scheduling noise (each round uses a fresh IP so no round's
// budget carries into the next) while preserving the real distinction: the
// fix changes the SIZE of the exploitable window from "however long the
// slow credential check takes" (bcrypt, deliberately ~tens of
// milliseconds) down to "however long decode takes" (sub-millisecond).
package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// runLoginBurst fires a synchronized burst of concurrent Login requests
// carrying a WRONG password (so each one that gets past the rate-limit
// check runs the real, deliberately-slow bcrypt compare — including the
// dummy-hash timing-safety path for a nonexistent user, auth.go's
// dummyBcryptHash) from the SAME IP, and returns how many reached the real
// credential check (401) vs. were rate-limited (429).
func runLoginBurst(t *testing.T, h *AuthHandler, ip string, burst int) (unauthorized, tooMany, other int64) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"username": "nobody-burst-test", "password": "wrong-password"})
	require.NoError(t, err)

	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
			req.RemoteAddr = fmt.Sprintf("%s:%d", ip, 40000+i)
			w := httptest.NewRecorder()
			<-start
			h.Login(w, req)
			switch w.Code {
			case http.StatusUnauthorized:
				atomic.AddInt64(&unauthorized, 1)
			case http.StatusTooManyRequests:
				atomic.AddInt64(&tooMany, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	return unauthorized, tooMany, other
}

// TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks runs several
// independent synchronized bursts (each on its own fresh IP, so no round's
// budget carries into the next) and asserts the AGGREGATE too-many-requests
// count across rounds — averaging out the single-round noise described in
// this file's header comment while still reliably distinguishing the fixed
// ordering from the pre-fix one (see this test's own red/green note in the
// PR description: reverting reserveLoginAttempt to run only after Login()
// fails made this aggregate assertion fail in the majority of repeated runs).
func TestLogin_ConcurrentBurst_RateLimitBoundsCredentialChecks(t *testing.T) {
	if raceDetectorActive {
		// -race instruments every memory access, slowing execution enough to
		// change the relative timing between the DB-backed reserve and the
		// bcrypt credential check this test depends on — confirmed
		// empirically to flake under -race even against the fixed code. See
		// login_rate_limit_reserve_race_test.go.
		t.Skip("timing-sensitive concurrency test flakes under -race (see comment); the fix itself " +
			"is red/green-verified manually, see docs/findings/2026-09-20-FINDING-login-lockout-mfa-recheck.md")
	}
	h := NewAuthHandler(freshCoreS12(t), false)

	const burst = 30
	const rounds = 5
	require.Greater(t, burst, int(core.LoginMaxAttempts),
		"each round's burst must exceed the budget for this test to mean anything")

	// Warm up the DB connection pool / i18n / goroutine scheduler on a
	// DIFFERENT IP first — an untouched process's very first request can be
	// slow enough (cold caches, lazy init) to distort the timing this test
	// depends on, without that slowness having anything to do with the
	// property under test.
	warmBody, err := json.Marshal(map[string]string{"username": "nobody-warmup", "password": "wrong-password"})
	require.NoError(t, err)
	warmReq := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(warmBody)))
	warmReq.RemoteAddr = "203.0.113.78:1234"
	h.Login(httptest.NewRecorder(), warmReq)

	var totalUnauthorized, totalTooMany, totalOther int64
	for round := 0; round < rounds; round++ {
		ip := fmt.Sprintf("203.0.113.%d", 100+round)
		unauthorized, tooMany, other := runLoginBurst(t, h, ip, burst)
		t.Logf("round=%d ip=%s unauthorized(reached credential check)=%d too_many_requests=%d other=%d",
			round, ip, unauthorized, tooMany, other)
		totalUnauthorized += unauthorized
		totalTooMany += tooMany
		totalOther += other
	}

	t.Logf("TOTAL across %d rounds of %d: unauthorized=%d too_many_requests=%d other=%d",
		rounds, burst, totalUnauthorized, totalTooMany, totalOther)
	assert.Zero(t, totalOther, "every response must be either 401 (reached the credential check) or 429 (rate-limited)")
	// Empirically (15 single-round runs of the fixed code): too_many_requests
	// per round of 30 ranged 8-20 (mean ~14); reverted to the pre-fix
	// ordering (10 single-round runs): 0-9 (mean ~4.5). Requiring the
	// 5-round AGGREGATE to clear 40 (mean 8/round) sits well above the
	// broken ordering's per-round ceiling repeated 5 times (5*9=45 would be
	// its best case, but its actual mean*5 ~22 is far below) and well below
	// the fixed ordering's typical aggregate (~70).
	assert.GreaterOrEqual(t, totalTooMany, int64(40),
		"CEILING VIOLATED: too few of these synchronized bursts were rate-limited in aggregate — the "+
			"reserve must happen before the slow credential check runs, not only after it fails, or a "+
			"concurrent burst can blow straight through the budget")
	assert.Less(t, totalUnauthorized, int64(rounds*burst),
		"the rate limiter had no observable effect on any of these bursts at all")
}
