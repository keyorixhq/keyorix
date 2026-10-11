// login_budget_fallback.go — the per-IP login budget's behaviour when its
// LoginAttempt storage fails (Andrei, 2026-10-10, AUTH-AUDIT-1).
//
// The budget used to fail OPEN on a storage error (IsLoginRateLimited answered
// "not limited", RecordFailedLogin/ReserveLoginAttempt recorded nothing), so a
// database fault, or an attacker able to provoke one, removed the brute-force
// backstop entirely. Failing CLOSED instead would lock every user out on a DB
// hiccup. The decision is neither: on a storage error the budget falls back to
// this in-memory limiter, with the SAME limit (LoginMaxAttempts) and window
// (LoginWindow), keyed by the same canonical client IP the stored budget uses
// (CanonicalIP of the address the transport's trusted-proxy logic resolved).
//
// What it is and is not:
//   - per process. In HA each replica enforces its own copy during an outage,
//     so the effective cluster-wide limit is up to LoginMaxAttempts per replica
//     the attacker can reach. Still a bound, where fail-open was none.
//   - bounded: at most loginFallbackMaxIPs addresses (least recently used is
//     evicted), and per address only the attempts inside the window, capped,
//     are kept. Many distinct (spoofed or rotating) addresses evict each other
//     rather than exhaust memory; rotating addresses already defeats any per-IP
//     limit, stored or not.
//   - consulted IN ADDITION to the stored count: memory only ever holds
//     attempts whose stored write failed, so OR-ing it in never double-counts,
//     and leftover entries age out with the window after storage recovers. The
//     counts are never merged into storage.
//   - releasable: a reservation taken here gets an id with loginFallbackIDBit
//     set, which no stored row id can carry, so ReleaseLoginAttempt (a
//     delivered login, #2936) refunds it here instead of in storage.
//
// Every fallback is audited (EventLoginBudgetFallback, Success=false) and
// counted (keyorix_login_budget_fallback_total). The client sees no
// difference: a refusal from memory is the same 429 a stored refusal is.
package core

import (
	"container/list"
	"context"
	"fmt"
	"math/bits"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EventLoginBudgetFallback is the error event written each time the login
// budget had to use the in-memory fallback because LoginAttempt storage failed.
const EventLoginBudgetFallback = "auth.rate_limit_error"

// loginFallbackMaxIPs bounds the fallback's memory: at most this many client
// addresses are tracked, least recently used evicted first.
const loginFallbackMaxIPs = 10_000

// loginFallbackMaxPerIP caps the attempts kept per address. Anything at or
// above LoginMaxAttempts already refuses; the headroom lets releases (delivered
// logins) refund without dropping a still-counted failure below the limit.
const loginFallbackMaxPerIP = 4 * LoginMaxAttempts

// loginFallbackIDBit marks a reservation id as the fallback's own. Stored
// LoginAttempt ids are database sequence values that never reach the top bit.
const loginFallbackIDBit uint = 1 << (bits.UintSize - 1)

var loginBudgetFallbackTotal = promauto.NewCounter(prometheus.CounterOpts{
	Name: "keyorix_login_budget_fallback_total",
	Help: "Count of per-IP login budget operations that fell back to the in-memory limiter because LoginAttempt storage failed.",
})

type loginFallbackAttempt struct {
	id uint
	at time.Time
}

type loginFallbackEntry struct {
	ip       string
	attempts []loginFallbackAttempt
}

// loginFallbackLimiter is the bounded in-memory per-IP window. Safe for
// concurrent use.
type loginFallbackLimiter struct {
	mu     sync.Mutex
	maxIPs int
	lru    *list.List               // front = most recently used; values *loginFallbackEntry
	byIP   map[string]*list.Element // ip -> element in lru
	byID   map[uint]string          // reservation id -> ip, for release
	nextID uint
}

func newLoginFallbackLimiter(maxIPs int) *loginFallbackLimiter {
	return &loginFallbackLimiter{
		maxIPs: maxIPs,
		lru:    list.New(),
		byIP:   map[string]*list.Element{},
		byID:   map[uint]string{},
	}
}

// loginBudgetFallback returns c's fallback limiter, created on first use so
// every way of constructing a KeyorixCore gets one.
func (c *KeyorixCore) loginBudgetFallback() *loginFallbackLimiter {
	c.loginFallbackOnce.Do(func() { c.loginFallback = newLoginFallbackLimiter(loginFallbackMaxIPs) })
	return c.loginFallback
}

// reserve records one attempt for ip at now and returns its id.
func (f *loginFallbackLimiter) reserve(ip string, now time.Time) uint {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.touch(ip)
	f.prune(e, now.Add(-LoginWindow))
	f.nextID++
	id := f.nextID | loginFallbackIDBit
	e.attempts = append(e.attempts, loginFallbackAttempt{id: id, at: now})
	f.byID[id] = ip
	if len(e.attempts) > loginFallbackMaxPerIP {
		delete(f.byID, e.attempts[0].id)
		e.attempts = e.attempts[1:]
	}
	return id
}

// count returns how many attempts ip has at or after since.
func (f *loginFallbackLimiter) count(ip string, since time.Time) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	el, ok := f.byIP[ip]
	if !ok {
		return 0
	}
	e := el.Value.(*loginFallbackEntry)
	f.prune(e, since)
	return len(e.attempts)
}

// release removes the reservation id, if this limiter still holds it.
func (f *loginFallbackLimiter) release(id uint) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ip, ok := f.byID[id]
	if !ok {
		return
	}
	delete(f.byID, id)
	el, ok := f.byIP[ip]
	if !ok {
		return
	}
	e := el.Value.(*loginFallbackEntry)
	for i, a := range e.attempts {
		if a.id == id {
			e.attempts = append(e.attempts[:i], e.attempts[i+1:]...)
			break
		}
	}
}

// size is the number of addresses currently tracked.
func (f *loginFallbackLimiter) size() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lru.Len()
}

// touch returns ip's entry, creating it (and evicting the least recently used
// address when full) as needed. Caller holds f.mu.
func (f *loginFallbackLimiter) touch(ip string) *loginFallbackEntry {
	if el, ok := f.byIP[ip]; ok {
		f.lru.MoveToFront(el)
		return el.Value.(*loginFallbackEntry)
	}
	for f.lru.Len() >= f.maxIPs {
		oldest := f.lru.Back()
		oe := oldest.Value.(*loginFallbackEntry)
		for _, a := range oe.attempts {
			delete(f.byID, a.id)
		}
		delete(f.byIP, oe.ip)
		f.lru.Remove(oldest)
	}
	e := &loginFallbackEntry{ip: ip}
	f.byIP[ip] = f.lru.PushFront(e)
	return e
}

// prune drops ip's attempts older than since. Caller holds f.mu.
func (f *loginFallbackLimiter) prune(e *loginFallbackEntry, since time.Time) {
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

// noteLoginBudgetFallback audits and counts one fallback. The audit write is
// best-effort like every audit write on this path; during a full outage it
// will usually fail too, which is why the metric exists.
func (c *KeyorixCore) noteLoginBudgetFallback(ctx context.Context, op, ip string, err error) {
	loginBudgetFallbackTotal.Inc()
	c.writeAuditEventFailed(ctx, EventLoginBudgetFallback, nil, nil, ip,
		fmt.Sprintf("login rate limit %s for %s fell back to the in-memory limiter: LoginAttempt storage error: %v", op, ip, err))
}
