// local_named_lock.go — general-purpose cross-replica serialization for check-then-act
// invariants that don't warrant their own bespoke WithXLock method (#1646).
package store

import (
	"context"
	"database/sql"
	"fmt"
	"hash/fnv"
	"sync"
)

// namedLockRegistry hands out one *sync.Mutex per lock key, creating it on
// first use, so the non-Postgres WithNamedLock fallback (SQLite,
// single-process by construction) serializes callers per-key exactly like
// PostgreSQL's pg_advisory_lock does -- not one shared mutex serializing every
// unrelated key against every other. FIX-5 (adversarial review run 2): this
// replaces a single process-wide *sync.Mutex that WAS shared across every
// lock key -- with the reentrancy guard now keyed on lockKey (see
// namedLockHeldCtxKey), a nested WithNamedLock call under a DIFFERENT key
// must actually be able to acquire its OWN lock rather than either
// (old, wrong) silently skipping it, or (a naive per-key reentrancy fix atop
// the OLD single shared mutex) self-deadlocking by re-locking the same mutex
// the outer call already holds.
//
// #1690 regression (Part 2 regression audit, 2026-09-04): FIX-5's own map
// (originally map[string]*sync.Mutex) never deleted an entry once created --
// lockKey's key space is per-entity (sodGrantLockKey("user"/"group", ID),
// projectAdminGuardLockKey(projectID)), so on a long-uptime SQLite/
// single-process deployment the map grows by one entry per distinct
// user/group/project ID ever role-managed and never shrinks: an unbounded
// memory-growth surface the old single-mutex design had no way to exhibit,
// by construction. Fixed with a refcounted entry: acquire increments refs
// under r.mu before locking the entry's own mutex; release decrements refs
// (also under r.mu) after unlocking it and deletes the map entry only once
// refs reaches zero -- i.e. only once no goroutine anywhere in the process is
// still holding or waiting on that specific entry. A racing acquire for the
// same key between another caller's unlock and its release either sees the
// entry still in the map (bumps refs, reuses the SAME mutex object -- no
// correctness gap) or finds it already deleted (creates a fresh one for a
// genuinely uncontended key) -- there is never a window where two different
// mutex objects are live for the same key at once.
type namedLockEntry struct {
	mu   sync.Mutex
	refs int // guarded by namedLockRegistry.mu, not by mu above
}

type namedLockRegistry struct {
	mu    sync.Mutex
	locks map[string]*namedLockEntry
}

func newNamedLockRegistry() *namedLockRegistry {
	return &namedLockRegistry{locks: make(map[string]*namedLockEntry)}
}

// acquire locks and returns the entry for lockKey, creating it if this is the
// first caller to ever name it (or if a prior entry was already reclaimed).
// The caller MUST pass the returned entry to release(lockKey, entry) exactly
// once, after its critical section, to unlock it and let the registry
// reclaim it once no one else is using it.
func (r *namedLockRegistry) acquire(lockKey string) *namedLockEntry {
	r.mu.Lock()
	e, ok := r.locks[lockKey]
	if !ok {
		e = &namedLockEntry{}
		r.locks[lockKey] = e
	}
	e.refs++
	r.mu.Unlock()
	e.mu.Lock()
	return e
}

// release unlocks e and, if no other caller is currently holding or waiting
// on it, removes lockKey's entry from the registry so its memory is
// reclaimed rather than retained for the rest of the process's lifetime.
func (r *namedLockRegistry) release(lockKey string, e *namedLockEntry) {
	e.mu.Unlock()
	r.mu.Lock()
	e.refs--
	if e.refs == 0 {
		delete(r.locks, lockKey)
	}
	r.mu.Unlock()
}

// namedLockKey derives a stable int64 advisory-lock key from an arbitrary lockKey
// string via FNV-1a (Go-side, not a Postgres SQL function, so the same key always
// hashes identically regardless of which connection computes it).
func namedLockKey(lockKey string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lockKey)) // fnv.Write never errors
	return int64(h.Sum64())         // #nosec G115 -- advisory-lock key, not a security boundary -- truncation to int64 range is fine
}

// namedLockHeldCtxKey marks a context as already running inside a WithNamedLock
// closure for one or more SPECIFIC lock keys (see heldNamedLockKeys). WithNamedLock
// is meant to guard against concurrent OTHER callers racing the same check-then-act
// sequence for a given lockKey; it is not meant to serialize a single call chain
// against itself reacquiring that SAME key. Without this guard, one guarded core
// method calling another under the identical key (e.g. SetProjectMemberRole →
// guardLastProjectAdmin's own re-entry, both keyed on projectAdminGuardLockKey)
// self-deadlocks: the SQLite/single-process path re-locks ls.namedLockMu (not
// reentrant), and the Postgres path pulls a SECOND connection from the pool and
// blocks it on pg_advisory_lock behind the first connection's own held lock —
// which, under a small pool, also starves connectionOpener into a permanent
// select (reproduced: internal/core's suite hung 600s on exactly this shape).
//
// FIX-5 (adversarial review run 2): the marker used to be a single untyped
// boolean, so ANY already-held lock -- regardless of key -- caused a nested
// WithNamedLock call under a DIFFERENT key to skip acquiring it entirely. That is
// the wrong invariant: WithNamedLock's whole point is per-key cross-replica
// serialization, and a nested call under a different key still needs its own
// lock actually taken (e.g. SetProjectMemberRole holds projectAdminGuardLockKey
// and calls AssignUserRole, which must still acquire its own
// sodGrantLockKey("user", userID) -- a different resource, not covered by the
// outer lock at all). The marker is now the SET of keys currently held by this
// call chain, so only a re-entrant acquisition of the SAME key is skipped.
type namedLockHeldCtxKey struct{}

// heldNamedLockKeys reads the set of lock keys already held by this call chain,
// or nil if none.
func heldNamedLockKeys(ctx context.Context) map[string]bool {
	held, _ := ctx.Value(namedLockHeldCtxKey{}).(map[string]bool)
	return held
}

// namedLockConnCtxKey carries the *sql.Conn an outer WithNamedLock call
// checked out of the pool, so a nested call under a DIFFERENT key (Postgres
// path only) reuses it instead of checking out a second connection.
//
// Part 2 regression audit (adversarial review run 2), found in FIX-5 itself:
// PostgreSQL advisory locks are SESSION-scoped, not per-acquisition -- one
// connection can hold pg_advisory_lock on any number of distinct keys at
// once. Before this, every WithNamedLock call (nested or not) pulled its own
// connection via sqlDB.Conn(ctx), so a call chain nesting N distinct keys
// needed N simultaneous pooled connections. Under a constrained pool (e.g.
// max_open_conns: 1 or 2, unenforced by internal/config), the outer call
// holds the pool's only connection for the ENTIRE duration of fn -- which is
// itself the blocked inner call waiting on sqlDB.Conn(ctx) for a connection
// only the outer call could release. Verified: an indefinite deadlock (not
// contention -- it never resolved on its own; only an artificial context
// timeout ended it), reproduced against real Postgres with MaxOpenConns(1).
// Reusing the outer call's connection for every nested key removes the
// per-chain connection-count dependency entirely: a chain nesting any number
// of distinct keys still needs only ONE pooled connection.
type namedLockConnCtxKey struct{}

func heldNamedLockConn(ctx context.Context) *sql.Conn {
	conn, _ := ctx.Value(namedLockConnCtxKey{}).(*sql.Conn)
	return conn
}

// WithNamedLock runs fn with every OTHER caller using the identical lockKey
// serialized against it: a per-key process-level mutex (namedLockRegistry)
// covers the common single-writer self-host topology and SQLite (inherently
// single-instance — there is no DB-level advisory lock to take); a PostgreSQL
// session-scoped advisory lock (pg_advisory_lock), keyed by lockKey's FNV-1a
// hash, extends that across processes/replicas (ADR-039 HA). Both paths give
// two DIFFERENT lock keys independent locks — only callers sharing the same
// key ever serialize against each other.
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock is
// acquired rather than skipping on contention — a caller that loses the race must
// actually re-run its check under the lock and observe the winner's now-committed
// state, not silently no-op.
//
// fn receives the (possibly lock-marked) context so that a nested WithNamedLock
// call made from within fn, under the SAME lockKey, sees the marker via
// namedLockHeldCtxKey and runs directly instead of re-acquiring: the outer lock
// already gives this call chain exclusivity over every other goroutine/replica
// for that key. A nested call under a DIFFERENT lockKey is not covered by the
// outer lock at all and still acquires its own. Callers that thread ctx through
// to further WithNamedLock calls MUST use the ctx passed to fn, not whatever ctx
// they closed over — otherwise the marker never propagates and a same-key nested
// call self-deadlocks (see namedLockHeldCtxKey).
func (ls *LocalStorage) WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
	held := heldNamedLockKeys(ctx)
	if held[lockKey] {
		return fn(ctx)
	}
	next := make(map[string]bool, len(held)+1)
	for k := range held {
		next[k] = true
	}
	next[lockKey] = true
	ctx = context.WithValue(ctx, namedLockHeldCtxKey{}, next)

	if ls.db.Dialector.Name() != "postgres" {
		entry := ls.namedLockMu.acquire(lockKey)
		defer ls.namedLockMu.release(lockKey, entry)
		return fn(ctx)
	}

	key := namedLockKey(lockKey)

	// Reuse an outer call's already-checked-out connection if this call chain
	// has one (see namedLockConnCtxKey) -- a nested call under a different key
	// must still acquire its OWN advisory lock, but never needs a SECOND
	// pooled connection to do it.
	if conn := heldNamedLockConn(ctx); conn != nil {
		if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
			return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
		}
		defer func() {
			_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key)
		}()
		return fn(ctx)
	}

	sqlDB, err := ls.db.DB()
	if err != nil {
		return err
	}
	conn, err := sqlDB.Conn(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // returns the conn to the pool (after the unlock below)

	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key)
	}()

	// Make this connection available to any nested WithNamedLock call under a
	// different key, for the remainder of this call chain.
	ctx = context.WithValue(ctx, namedLockConnCtxKey{}, conn)
	return fn(ctx)
}
