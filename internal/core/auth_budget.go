// auth_budget.go — the one limiter every authentication budget goes through,
// and its behaviour when the budget's storage fails (Andrei, 2026-10-10:
// login budget at 17:52; "no auth budget ever fails open on storage errors"
// at 18:52, AUTH-AUDIT-1).
//
// The budgets:
//
//	login            per IP, LoginMaxAttempts per LoginWindow, login_attempts
//	                 (login, MFA verify, refresh, WebAuthn begin/finish,
//	                 passwordless begin/finish, setup-link consume)
//	password_reset   per IP, PasswordResetMaxAttempts per PasswordResetWindow,
//	                 login_attempts under "pwreset:"
//	sso_begin        per IP, SSOBeginMaxAttempts per SSOBeginWindow,
//	                 login_attempts under "sso:" (OIDC and SAML begin)
//	account_lockout  per account, LoginLockoutPolicy.MaxAttempts per Window,
//	                 the user row's lockout columns (password, TOTP, recovery
//	                 code, step-up, WebAuthn second factor and re-auth)
//
// Each used to fail OPEN on a storage error: a count that could not be read
// answered "not limited", and an attempt that could not be written was not
// counted, so a database fault, or an attacker able to provoke one, removed
// the brute-force backstop entirely. Failing CLOSED instead would lock every
// user out on a DB hiccup. The decision is neither: on a storage error the
// budget falls back to a bounded in-memory limiter with the SAME limit and
// window, keyed the same way (the canonical client IP the transport's
// trusted-proxy logic resolved, or the account id).
//
// What the fallback is and is not:
//   - per process. In HA each replica enforces its own copy during an outage,
//     so the effective cluster-wide limit is up to the limit per replica the
//     attacker can reach. Still a bound, where fail-open was none.
//   - bounded: one limiter per budget, each holding at most authFallbackMaxKeys
//     keys (least recently used evicted first), and per key only the attempts
//     inside the window, capped at 4x the limit. Many distinct (spoofed or
//     rotating) addresses evict each other rather than exhaust memory, and
//     cannot evict another budget's entries (an account's in-memory lock is
//     not displaced by an IP flood).
//   - consulted IN ADDITION to the stored count: memory only ever holds
//     attempts whose stored write failed, so adding it never double-counts,
//     and leftover entries age out with the window after storage recovers. The
//     counts are never merged into storage.
//   - releasable (login only): a reservation taken here gets an id with
//     authFallbackIDBit set, which no stored row id can carry, so
//     ReleaseLoginAttempt (a delivered login, #2936) refunds it here.
//   - for account_lockout, no exponential cooldown: an account is locked while
//     MaxAttempts in-memory failures fall inside Window, and unlocks as they
//     age out. A delivered login and an admin unlock clear the entry, as they
//     clear the stored columns.
//
// While a budget is on its fallback (item 5, points 2-4):
//   - the in-memory count is held to the budget's fallback limit: its limit
//     divided by fallbackDivisor (2 for password reset: half the per-IP limit)
//     and by the configured replica count (SetAuthRateLimitFallbackReplicas,
//     default 1), never below 1. A stored count that could be read is
//     cluster-wide already and keeps the normal limit.
//   - password reset also caps resets per account (passwordResetAccountBudget,
//     checked in RequestPasswordReset): the email-bombing guard.
//   - AuthRateLimitDegraded reports true until no budget has fallen back within
//     its window, for the health endpoint.
//
// Every fallback is audited (EventAuthRateLimitError, Success=false) and
// counted (keyorix_auth_rate_limit_fallback_total{budget}). The client sees no
// difference: a refusal from memory is the same response a stored refusal is.
package core

import (
	"container/list"
	"context"
	"fmt"
	"math/bits"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EventAuthRateLimitError is the error event written each time an auth budget
// had to use the in-memory fallback because its storage failed.
const EventAuthRateLimitError = "auth.rate_limit_error"

// authBudget names one budget: its key namespace in login_attempts, its limit
// and its window. fallbackDivisor (0 means 1) tightens the limit while the
// budget runs on its in-memory fallback.
type authBudget struct {
	name            string
	prefix          string
	limit           int
	window          time.Duration
	fallbackDivisor int
}

var (
	loginBudget         = authBudget{name: "login", limit: LoginMaxAttempts, window: LoginWindow}
	passwordResetBudget = authBudget{name: "password_reset", prefix: passwordResetRateLimitPrefix, limit: PasswordResetMaxAttempts, window: PasswordResetWindow, fallbackDivisor: 2}
	// passwordResetAccountBudget caps resets per account while
	// passwordResetBudget is on its fallback (memory only; see
	// RequestPasswordReset). Same limit, window and divisor as the per-IP one.
	passwordResetAccountBudget = authBudget{name: "password_reset_account", limit: PasswordResetMaxAttempts, window: PasswordResetWindow, fallbackDivisor: 2}
	ssoBeginBudget             = authBudget{name: "sso_begin", prefix: ssoRateLimitPrefix, limit: SSOBeginMaxAttempts, window: SSOBeginWindow}
	// accountLockoutBudget's limit and window come from the core's
	// LoginLockoutPolicy; see accountBudget.
	accountLockoutBudget = authBudget{name: "account_lockout"}
)

// accountBudget is accountLockoutBudget with this core's lockout policy.
func (c *KeyorixCore) accountBudget() authBudget {
	b := accountLockoutBudget
	b.limit = c.loginLockout.MaxAttempts
	b.window = c.loginLockout.Window
	return b
}

func accountBudgetKey(userID uint) string { return strconv.FormatUint(uint64(userID), 10) }

// authFallbackMaxKeys bounds each budget's fallback: at most this many keys
// are tracked, least recently used evicted first.
const authFallbackMaxKeys = 10_000

// authFallbackIDBit marks a reservation id as the fallback's own. Stored
// LoginAttempt ids are database sequence values that never reach the top bit.
const authFallbackIDBit uint = 1 << (bits.UintSize - 1)

var authRateLimitFallbackTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "keyorix_auth_rate_limit_fallback_total",
	Help: "Count of auth rate-limit operations that fell back to the in-memory limiter because the budget's storage failed.",
}, []string{"budget"})

// SetAuthRateLimitFallbackReplicas sets how many server replicas share the
// auth budgets (security.auth_rate_limit_fallback.replicas). Each replica's
// in-memory fallback then enforces 1/n of a budget's fallback limit, so the
// cluster as a whole stays near the normal limit during an outage. n < 1 is
// treated as 1. Called once at startup.
func (c *KeyorixCore) SetAuthRateLimitFallbackReplicas(n int) {
	if n < 1 {
		n = 1
	}
	c.authFallbackReplicas.Store(int64(n))
}

// fallbackLimit is b's limit while it runs on the in-memory fallback.
func (c *KeyorixCore) fallbackLimit(b authBudget) int {
	div := int64(1)
	if b.fallbackDivisor > 1 {
		div = int64(b.fallbackDivisor)
	}
	if r := c.authFallbackReplicas.Load(); r > 1 {
		div *= r
	}
	limit := int64(b.limit) / div
	if limit < 1 {
		limit = 1
	}
	return int(limit)
}

// AuthRateLimitDegraded reports whether any auth budget has used its in-memory
// fallback within that budget's window, i.e. whether a fallback may still be
// deciding. For the health endpoint; it names no budget, key or address.
func (c *KeyorixCore) AuthRateLimitDegraded() bool {
	now := c.now()
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	for _, m := range c.authFallbackLast {
		if now.Sub(m.at) <= m.window {
			return true
		}
	}
	return false
}

// budgetDegraded reports whether b itself has fallen back within its window.
func (c *KeyorixCore) budgetDegraded(b authBudget) bool {
	now := c.now()
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	m, ok := c.authFallbackLast[b.name]
	return ok && now.Sub(m.at) <= m.window
}

// --- the stored budget, with the fallback behind it -------------------------

// budgetLimited reports whether key has spent b within its window: the stored
// count plus the fallback's against the normal limit, or the fallback's alone
// against the fallback limit. A stored count that cannot be read counts as 0.
func (c *KeyorixCore) budgetLimited(ctx context.Context, b authBudget, key string) bool {
	since := c.now().Add(-b.window)
	mem := int64(c.authBudgetFallback(b).count(key, since))
	if mem >= int64(c.fallbackLimit(b)) {
		return true
	}
	n, err := c.storage.CountRecentLoginAttempts(ctx, b.prefix+key, since)
	if err != nil {
		c.noteAuthBudgetFallback(ctx, b, "check", key, nil, err)
		return false
	}
	return n+mem >= int64(b.limit)
}

// budgetRecord counts one attempt against key, in memory when storage fails.
func (c *KeyorixCore) budgetRecord(ctx context.Context, b authBudget, key string) {
	if err := c.storage.RecordLoginAttempt(ctx, b.prefix+key, c.now()); err != nil {
		c.budgetRecordFallback(ctx, b, key, nil, err)
	}
}

// budgetReserve is budgetRecord returning a handle budgetRelease can refund.
func (c *KeyorixCore) budgetReserve(ctx context.Context, b authBudget, key string) uint {
	id, err := c.storage.ReserveLoginAttempt(ctx, b.prefix+key, c.now())
	if err != nil {
		c.noteAuthBudgetFallback(ctx, b, "reserve", key, nil, err)
		return c.authBudgetFallback(b).reserve(key, c.now(), b.window, 4*b.limit)
	}
	return id
}

// budgetReleaseStored refunds a stored reservation. A fallback id goes to
// budgetReleaseFallback instead (see ReleaseLoginAttempt).
func (c *KeyorixCore) budgetReleaseStored(ctx context.Context, id uint) error {
	return c.storage.ReleaseLoginAttempt(ctx, id)
}

// budgetReleaseFallback refunds a reservation the fallback took.
func (c *KeyorixCore) budgetReleaseFallback(b authBudget, id uint) {
	c.authBudgetFallback(b).release(id)
}

// --- the fallback alone, for a budget stored elsewhere (account_lockout) -----

// budgetRecordFallback counts one attempt in memory because the budget's own
// stored write failed with err. userID, when set, attributes the audit event.
func (c *KeyorixCore) budgetRecordFallback(ctx context.Context, b authBudget, key string, userID *uint, err error) {
	c.noteAuthBudgetFallback(ctx, b, "record", key, userID, err)
	c.authBudgetFallback(b).reserve(key, c.now(), b.window, 4*b.limit)
}

// budgetFallbackLimited reports whether the fallback alone has key at b's
// fallback limit.
func (c *KeyorixCore) budgetFallbackLimited(b authBudget, key string) bool {
	return b.limit > 0 && c.authBudgetFallback(b).count(key, c.now().Add(-b.window)) >= c.fallbackLimit(b)
}

// budgetFallbackTryReserve counts one attempt for key in memory if key is
// still under b's fallback limit, atomically, and reports whether it did.
func (c *KeyorixCore) budgetFallbackTryReserve(b authBudget, key string) bool {
	return c.authBudgetFallback(b).tryReserve(key, c.now(), b.window, 4*b.limit, c.fallbackLimit(b))
}

// budgetFallbackClear forgets key's in-memory attempts.
func (c *KeyorixCore) budgetFallbackClear(b authBudget, key string) {
	c.authBudgetFallback(b).clear(key)
}

// noteAuthBudgetFallback audits and counts one fallback. The audit write is
// best-effort like every audit write on this path; during a full outage it
// will usually fail too, which is why the metric exists.
func (c *KeyorixCore) noteAuthBudgetFallback(ctx context.Context, b authBudget, op, key string, userID *uint, err error) {
	authRateLimitFallbackTotal.WithLabelValues(b.name).Inc()
	c.authFallbackMu.Lock()
	if c.authFallbackLast == nil {
		c.authFallbackLast = map[string]authFallbackMark{}
	}
	c.authFallbackLast[b.name] = authFallbackMark{at: c.now(), window: b.window}
	c.authFallbackMu.Unlock()
	ip := key
	if userID != nil {
		ip = ""
	}
	c.writeAuditEventFailed(ctx, EventAuthRateLimitError, userID, nil, ip,
		fmt.Sprintf("%s rate limit %s for %s fell back to the in-memory limiter: storage error: %v", b.name, op, key, err))
}

// authBudgetFallback returns c's fallback limiter for b, created on first use
// so every way of constructing a KeyorixCore gets one.
func (c *KeyorixCore) authBudgetFallback(b authBudget) *authFallbackLimiter {
	c.authFallbackMu.Lock()
	defer c.authFallbackMu.Unlock()
	if c.authFallbacks == nil {
		c.authFallbacks = map[string]*authFallbackLimiter{}
	}
	f, ok := c.authFallbacks[b.name]
	if !ok {
		f = newAuthFallbackLimiter(authFallbackMaxKeys)
		c.authFallbacks[b.name] = f
	}
	return f
}

// authFallbackMark is when a budget last fell back, and how long its
// in-memory attempts live.
type authFallbackMark struct {
	at     time.Time
	window time.Duration
}

// --- the bounded in-memory window -------------------------------------------

type authFallbackAttempt struct {
	id uint
	at time.Time
}

type authFallbackEntry struct {
	key      string
	attempts []authFallbackAttempt
}

// authFallbackLimiter is a bounded in-memory per-key sliding window. Safe for
// concurrent use.
type authFallbackLimiter struct {
	mu      sync.Mutex
	maxKeys int
	lru     *list.List               // front = most recently used; values *authFallbackEntry
	byKey   map[string]*list.Element // key -> element in lru
	byID    map[uint]string          // reservation id -> key, for release
	nextID  uint
}

func newAuthFallbackLimiter(maxKeys int) *authFallbackLimiter {
	return &authFallbackLimiter{
		maxKeys: maxKeys,
		lru:     list.New(),
		byKey:   map[string]*list.Element{},
		byID:    map[uint]string{},
	}
}

// reserve records one attempt for key at now, keeping at most maxPerKey
// attempts inside window, and returns its id.
func (f *authFallbackLimiter) reserve(key string, now time.Time, window time.Duration, maxPerKey int) uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(key)
	f.prune(e, now.Add(-window))
	f.add(e, now, maxPerKey)
	return e.attempts[len(e.attempts)-1].id
}

// tryReserve is reserve, but only while key has fewer than limit attempts
// inside window; the check and the record happen under one lock.
func (f *authFallbackLimiter) tryReserve(key string, now time.Time, window time.Duration, maxPerKey, limit int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(key)
	f.prune(e, now.Add(-window))
	if len(e.attempts) >= limit {
		return false
	}
	f.add(e, now, maxPerKey)
	return true
}

// add appends one attempt to e (it becomes e's last), dropping the oldest
// beyond maxPerKey. Caller holds f.mu.
func (f *authFallbackLimiter) add(e *authFallbackEntry, now time.Time, maxPerKey int) {
	if maxPerKey < 1 {
		maxPerKey = 1 // a zero limit still keeps the attempt just added
	}
	f.nextID++
	id := f.nextID | authFallbackIDBit
	e.attempts = append(e.attempts, authFallbackAttempt{id: id, at: now})
	f.byID[id] = e.key
	if len(e.attempts) > maxPerKey {
		delete(f.byID, e.attempts[0].id)
		e.attempts = e.attempts[1:]
	}
}

// count returns how many attempts key has at or after since.
func (f *authFallbackLimiter) count(key string, since time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byKey[key]
	if !ok {
		return 0
	}
	e := el.Value.(*authFallbackEntry)
	f.prune(e, since)
	return len(e.attempts)
}

// release removes the reservation id, if this limiter still holds it.
func (f *authFallbackLimiter) release(id uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key, ok := f.byID[id]
	if !ok {
		return
	}
	delete(f.byID, id)
	el, ok := f.byKey[key]
	if !ok {
		return
	}
	e := el.Value.(*authFallbackEntry)
	for i, a := range e.attempts {
		if a.id == id {
			e.attempts = append(e.attempts[:i], e.attempts[i+1:]...)
			break
		}
	}
}

// clear forgets every attempt for key.
func (f *authFallbackLimiter) clear(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byKey[key]
	if !ok {
		return
	}
	for _, a := range el.Value.(*authFallbackEntry).attempts {
		delete(f.byID, a.id)
	}
	delete(f.byKey, key)
	f.lru.Remove(el)
}

// size is the number of keys currently tracked.
func (f *authFallbackLimiter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lru.Len()
}

// touch returns key's entry, creating it (and evicting the least recently used
// key when full) as needed. Caller holds f.mu.
func (f *authFallbackLimiter) touch(key string) *authFallbackEntry {
	if el, ok := f.byKey[key]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*authFallbackEntry)
	}
	for f.lru.Len() >= f.maxKeys {
		oldest := f.lru.Back()
		oe := oldest.Value.(*authFallbackEntry)
		for _, a := range oe.attempts {
			delete(f.byID, a.id)
		}
		delete(f.byKey, oe.key)
		f.lru.Remove(oldest)
	}
	e := &authFallbackEntry{key: key}
	f.byKey[key] = f.lru.PushFront(e)
	return e
}

// prune drops e's attempts older than since. Caller holds f.mu.
func (f *authFallbackLimiter) prune(e *authFallbackEntry, since time.Time) {
	keep := e.attempts[:0]
	for _, a := range e.attempts {
		if a.at.Before(since) {
			delete(f.byID, a.id)
			continue
		}
		keep = append(keep, a)
	}
	e.attempts = keep
}
