// local_named_lock.go — general-purpose cross-replica serialization for check-then-act
// invariants that don't warrant their own bespoke WithXLock method (#1646).
package store

import (
	"context"
	"fmt"
	"hash/fnv"
)

// namedLockKey derives a stable int64 advisory-lock key from an arbitrary lockKey
// string via FNV-1a (Go-side, not a Postgres SQL function, so the same key always
// hashes identically regardless of which connection computes it).
func namedLockKey(lockKey string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(lockKey)) // fnv.Write never errors
	return int64(h.Sum64())         // #nosec G115 -- advisory-lock key, not a security boundary -- truncation to int64 range is fine
}

// namedLockHeldCtxKey marks a context as already running inside a WithNamedLock
// closure. WithNamedLock is meant to guard against concurrent OTHER callers
// racing the same check-then-act sequence; it is not meant to serialize a single
// call chain against itself. Without this guard, one guarded core method calling
// another (e.g. SetProjectMemberRole → AssignUserRole, both #1646 call sites)
// self-deadlocks: the SQLite/single-process path re-locks ls.namedLockMu (not
// reentrant), and the Postgres path pulls a SECOND connection from the pool and
// blocks it on pg_advisory_lock behind the first connection's own held lock —
// which, under a small pool, also starves connectionOpener into a permanent
// select (reproduced: internal/core's suite hung 600s on exactly this shape).
type namedLockHeldCtxKey struct{}

// WithNamedLock runs fn with every OTHER caller using the identical lockKey
// serialized against it: a process-level mutex covers the common single-writer
// self-host topology and SQLite (inherently single-instance — there is no DB-level
// advisory lock to take); a PostgreSQL session-scoped advisory lock (pg_advisory_lock),
// keyed by lockKey's FNV-1a hash, extends that across processes/replicas (ADR-039 HA).
//
// Like WithBootstrapLock/WithAuditCheckpointLock, this BLOCKS until the lock is
// acquired rather than skipping on contention — a caller that loses the race must
// actually re-run its check under the lock and observe the winner's now-committed
// state, not silently no-op.
//
// fn receives the (possibly lock-marked) context so that a nested WithNamedLock
// call made from within fn — even under a different lockKey — sees the marker
// via namedLockHeldCtxKey and runs directly instead of re-acquiring: the outer
// lock already gives this call chain exclusivity over every other goroutine/replica.
// Callers that thread ctx through to further WithNamedLock calls MUST use the
// ctx passed to fn, not whatever ctx they closed over — otherwise the marker
// never propagates and the nested call self-deadlocks (see namedLockHeldCtxKey).
func (ls *LocalStorage) WithNamedLock(ctx context.Context, lockKey string, fn func(ctx context.Context) error) error {
	if ctx.Value(namedLockHeldCtxKey{}) != nil {
		return fn(ctx)
	}
	ctx = context.WithValue(ctx, namedLockHeldCtxKey{}, true)

	if ls.db.Dialector.Name() != "postgres" {
		ls.namedLockMu.Lock()
		defer ls.namedLockMu.Unlock()
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
