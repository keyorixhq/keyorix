package store

import (
	"context"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func newNamedLockTestStore(t *testing.T) *LocalStorage {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	return NewLocalStorage(db)
}

// A same-key nested WithNamedLock call must be skipped (not re-acquired) --
// this is the original #1646 self-deadlock guard, and must still hold after
// FIX-5 keys the guard on lockKey.
func TestWithNamedLock_ReentrantSameKey_DoesNotDeadlock(t *testing.T) {
	ls := newNamedLockTestStore(t)
	ctx := context.Background()

	done := make(chan error, 1)
	go func() {
		done <- ls.WithNamedLock(ctx, "same-key", func(ctx context.Context) error {
			return ls.WithNamedLock(ctx, "same-key", func(ctx context.Context) error {
				return nil
			})
		})
	}()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("same-key reentrant WithNamedLock call deadlocked")
	}
}

// FIX-5 (adversarial review run 2): a nested WithNamedLock call under a
// DIFFERENT key from the one already held must actually acquire its own
// lock, not silently skip acquisition because SOME lock (a different one) is
// already held by this call chain. Before this fix, the reentrancy guard was
// a single untyped boolean keyed on "is any lock held at all" -- so
// SetProjectMemberRole holding projectAdminGuardLockKey(projectID) and then
// calling AssignUserRole, which needs its own sodGrantLockKey("user", userID),
// never actually took the second lock, losing AssignUserRole's cross-replica
// SoD check-then-act serialization entirely whenever reached through that
// call chain.
//
// Proven here by holding "key-B" open in one goroutine and confirming a
// nested WithNamedLock(ctx, "key-B", ...) call -- issued from inside an outer
// WithNamedLock(ctx, "key-A", ...) closure on a SEPARATE call chain -- blocks
// until the first goroutine releases it. Under the old bug, the nested call
// would return immediately (wrongly treating key-B as already covered by
// key-A's own lock), which this test's ordering assertion would catch.
func TestWithNamedLock_NestedDifferentKey_StillSerializesAgainstOtherHolder(t *testing.T) {
	ls := newNamedLockTestStore(t)
	ctx := context.Background()

	const holdKey = "key-B"
	holderEntered := make(chan struct{})
	releaseHolder := make(chan struct{})
	holderDone := make(chan error, 1)

	go func() {
		holderDone <- ls.WithNamedLock(context.Background(), holdKey, func(ctx context.Context) error {
			close(holderEntered)
			<-releaseHolder
			return nil
		})
	}()

	select {
	case <-holderEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("holder goroutine never entered its critical section")
	}

	var releasedBeforeNestedAcquired bool
	nestedDone := make(chan error, 1)
	go func() {
		nestedDone <- ls.WithNamedLock(ctx, "key-A", func(ctx context.Context) error {
			// A DIFFERENT call chain (this goroutine) than the holder above is
			// currently blocking on holdKey. This nested call, under a
			// different key than "key-A", must still contend for holdKey's
			// own lock rather than skipping acquisition.
			return ls.WithNamedLock(ctx, holdKey, func(ctx context.Context) error {
				releasedBeforeNestedAcquired = true
				return nil
			})
		})
	}()

	// Give the nested call every opportunity to (wrongly) complete early if
	// the reentrancy guard were still skipping on "any lock held" rather than
	// "this exact key held" -- it must NOT have finished yet.
	select {
	case <-nestedDone:
		t.Fatal("nested WithNamedLock(key-B) returned before the other holder released it -- " +
			"the different-key lock was skipped instead of actually acquired")
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseHolder)

	select {
	case err := <-holderDone:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("holder goroutine never completed")
	}

	select {
	case err := <-nestedDone:
		require.NoError(t, err)
		require.True(t, releasedBeforeNestedAcquired)
	case <-time.After(5 * time.Second):
		t.Fatal("nested WithNamedLock(key-B) never completed after the holder released")
	}
}
