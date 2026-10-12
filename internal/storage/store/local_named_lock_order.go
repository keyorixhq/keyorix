// local_named_lock_order.go — test-build enforcement of storage.NamedLockOrder
// (C-GUARD-3 guard 3) on every WithNamedLock acquisition.
package store

import (
	"context"
	"sync/atomic"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// namedLockOrderCheck is off in production: nothing outside a _test.go file
// calls EnableNamedLockOrderCheckForTesting. internal/core's test binary turns
// it on for its whole suite (named_lock_order_enable_test.go).
var namedLockOrderCheck atomic.Bool

// EnableNamedLockOrderCheckForTesting makes every subsequent WithNamedLock
// call in this process panic when it would acquire a key out of
// storage.NamedLockOrder relative to the keys its call chain already holds.
// Test binaries only — a panic in a request handler is not how production
// should learn about a lock-order bug.
func EnableNamedLockOrderCheckForTesting() { namedLockOrderCheck.Store(true) }

// namedLockStackCtxKey carries the keys this call chain holds, in acquisition
// order (namedLockHeldCtxKey is a set and loses the order).
type namedLockStackCtxKey struct{}

// checkNamedLockOrder is called by WithNamedLock for a key not already held.
// With the check off it returns ctx unchanged and records nothing.
func checkNamedLockOrder(ctx context.Context, lockKey string) context.Context {
	if !namedLockOrderCheck.Load() {
		return ctx
	}
	stack, _ := ctx.Value(namedLockStackCtxKey{}).([]string)
	if err := storage.CheckNamedLockOrder(stack, lockKey); err != nil {
		panic(err.Error())
	}
	next := make([]string, len(stack), len(stack)+1)
	copy(next, stack)
	return context.WithValue(ctx, namedLockStackCtxKey{}, append(next, lockKey))
}
