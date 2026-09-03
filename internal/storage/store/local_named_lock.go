// local_named_lock.go — general-purpose cross-replica serialization for check-then-act
// invariants that don't warrant their own bespoke WithXLock method (#1646).
package store

import (
	"context"
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
type namedLockRegistry struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func newNamedLockRegistry() *namedLockRegistry {
	return &namedLockRegistry{locks: make(map[string]*sync.Mutex)}
}

// forKey returns the mutex for lockKey, creating it if this is the first
// caller to ever name it. The registry's own mu only guards the map lookup
// itself, not the returned mutex's Lock/Unlock -- callers hold the returned
// mutex for the duration of their critical section, same as before this type
// existed.
func (r *namedLockRegistry) forKey(lockKey string) *sync.Mutex {
	r.mu.Lock()
	defer r.mu.Unlock()
	m, ok := r.locks[lockKey]
	if !ok {
		m = &sync.Mutex{}
		r.locks[lockKey] = m
	}
	return m
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
		mu := ls.namedLockMu.forKey(lockKey)
		mu.Lock()
		defer mu.Unlock()
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

	key := namedLockKey(lockKey)
	if _, err := conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return fmt.Errorf("failed to acquire named advisory lock %q: %w", lockKey, err)
	}
	// Release before the deferred Close so the pooled connection carries no lock.
	defer func() {
		_, _ = conn.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", key)
	}()

	return fn(ctx)
}
