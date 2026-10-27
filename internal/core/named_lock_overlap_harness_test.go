// named_lock_overlap_harness_test.go — a fake WithNamedLock backend that
// reproduces the lock-loss overlap window of docs/design/pooler-lock-loss.md
// (POOLER-LOCKLOSS-1, #3622) for one critical section, deterministically.
//
// On PostgreSQL a WithNamedLock holder whose lock connection dies keeps running
// until the liveness ping notices (up to 5 s + 5 s), while another replica may
// already hold the same key. This harness plays both replicas:
//
//  1. The first holder (holder A, the core under test, wrapped in the hook
//     store) is granted the key by the fake backend and runs its section.
//  2. At A's first WithTransaction, i.e. after every check A makes before its
//     write transaction, the lock is "lost": the second holder (holder B, a
//     separate KeyorixCore over the same database, as a second replica would
//     be) runs its whole operation and commits.
//  3. A then continues into its write transaction.
//
// So the harness asks one question of a section: does what A does INSIDE its
// write transaction still keep the invariant once B's write has committed? A
// section whose only check runs before the transaction fails it; a section
// that re-checks in the transaction passes. It does not model two write
// transactions open at the same time (on PostgreSQL that needs a row lock both
// take; see named_lock_overlap_postgres_test.go).
//
// B runs on its own core because in-process mutexes (accountStateMu,
// globalAdminGuardMu, ...) are per replica: B on A's core would deadlock on a
// mutex A holds, which no two replicas can do.
package core_test

import (
	"context"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/core/storage/storagetest"
)

type overlapHolderKey struct{}

// lockLossOverlap is the fake backend for one key. Build it with
// newLockLossOverlap, wrap holder A's storage with store(), and read secondErr
// and fired after A's call returns.
type lockLossOverlap struct {
	t      *testing.T
	key    string
	second func(ctx context.Context) error

	mu        sync.Mutex
	granted   bool // the key was granted to A
	fired     bool // B ran inside A's section
	secondErr error
}

func newLockLossOverlap(t *testing.T, key string, second func(ctx context.Context) error) *lockLossOverlap {
	t.Helper()
	return &lockLossOverlap{t: t, key: key, second: second}
}

// store wraps inner (holder A's storage) with the fake backend.
func (o *lockLossOverlap) store(inner storage.Storage) storage.Storage {
	return storagetest.Hooked(inner, &storagetest.StoreHooks{
		// Every key is granted without blocking: A is the only caller of this
		// store. The first acquisition of o.key marks A's section in ctx.
		WithNamedLock: func(_ storage.Storage, ctx context.Context, key string, fn func(context.Context) error) error {
			o.mu.Lock()
			first := key == o.key && !o.granted
			if first {
				o.granted = true
			}
			o.mu.Unlock()
			if first {
				ctx = context.WithValue(ctx, overlapHolderKey{}, true)
			}
			return fn(ctx)
		},
		WithTransaction: func(next storage.Storage, ctx context.Context, fn func(storage.Storage) error) error {
			if ctx.Value(overlapHolderKey{}) != nil {
				o.mu.Lock()
				run := !o.fired
				o.fired = true
				o.mu.Unlock()
				if run {
					// The lock is lost here: B takes the key and finishes.
					o.secondErr = o.second(context.Background())
				}
			}
			return next.WithTransaction(ctx, fn)
		},
	})
}

// requireFired fails the test if B never ran inside A's section (the section
// opened no transaction under o.key, so the harness tested nothing).
func (o *lockLossOverlap) requireFired() {
	o.t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.granted || !o.fired {
		o.t.Fatalf("overlap harness: key %q granted=%v, second holder ran=%v: the section under test was not exercised", o.key, o.granted, o.fired)
	}
}
