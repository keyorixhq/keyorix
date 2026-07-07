package http

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
	"github.com/keyorixhq/keyorix/internal/storage/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newUpstreamDownstreamForSchedulerLock builds the standard #452/#507-style
// two-server harness (see remote_storage_machine_identities_test.go's
// newUpstreamDownstreamForMachineIdentities for the full pattern doc): an
// "upstream" exercised through the REAL production NewRouter/handlers
// (including the new /api/v1/system/scheduler-lock routes,
// server/http/handlers/scheduler_lock_proxy.go), and a "downstream"
// *core.KeyorixCore configured with storage.type: remote (ADR-049), pointed at
// "upstream" over real HTTP via store.RemoteStorage.
func newUpstreamDownstreamForSchedulerLock(t *testing.T) (upstream *core.KeyorixCore, downstream *core.KeyorixCore) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	upstream = newTestCore(t)
	upstreamToken := createTestToken(t, upstream)

	cfg := &config.Config{
		Server: config.ServerConfig{
			HTTP: config.ServerInstanceConfig{Enabled: true, Port: "0"},
		},
	}
	upstreamRouter, err := NewRouter(cfg, upstream)
	require.NoError(t, err)
	upstreamSrv := httptest.NewServer(upstreamRouter)
	t.Cleanup(upstreamSrv.Close)

	rs, err := store.NewRemoteStorage(&remote.Config{
		BaseURL:        upstreamSrv.URL,
		APIKey:         upstreamToken,
		TimeoutSeconds: 5,
		RetryAttempts:  0,
		TLSVerify:      true,
	})
	require.NoError(t, err)
	downstream = core.NewKeyorixCore(rs)
	return upstream, downstream
}

// TestRemoteStorageSchedulerLock_AcquireRunRelease_RealServer proves the basic
// fix end to end: a downstream (storage.type: remote) WithSchedulerLock call
// genuinely acquires a lease row on the upstream, runs fn, and releases it —
// so a SECOND, sequential call for the same key succeeds again immediately
// (proving release actually happened, not just that the TTL hadn't expired
// yet).
func TestRemoteStorageSchedulerLock_AcquireRunRelease_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSchedulerLock(t)
	ctx := context.Background()

	var ran1 bool
	ok, err := downstream.Storage().WithSchedulerLock(ctx, 4242, func() error {
		ran1 = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ok, "an uncontended lock must be acquired via storage.type: remote")
	assert.True(t, ran1, "fn must run when the lock is acquired")

	var ran2 bool
	ok, err = downstream.Storage().WithSchedulerLock(ctx, 4242, func() error {
		ran2 = true
		return nil
	})
	require.NoError(t, err)
	assert.True(t, ok, "a second sequential call must re-acquire the SAME key — proving the first call actually released it")
	assert.True(t, ran2)
}

// TestRemoteStorageSchedulerLock_ContendedLockIsSkipped_RealServer proves a
// lock genuinely held by one holder (via the low-level
// TryAcquireSchedulerLock primitive, simulating a second live scheduler
// replica) blocks a second WithSchedulerLock caller for the SAME key: it
// returns (false, nil) — "skip this tick" — rather than running fn.
func TestRemoteStorageSchedulerLock_ContendedLockIsSkipped_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSchedulerLock(t)
	ctx := context.Background()

	acquired, err := downstream.Storage().TryAcquireSchedulerLock(ctx, 777, "other-replica", time.Minute)
	require.NoError(t, err)
	require.True(t, acquired)

	ran := false
	ok, err := downstream.Storage().WithSchedulerLock(ctx, 777, func() error {
		ran = true
		return nil
	})
	require.NoError(t, err, "a skipped tick is not an error")
	assert.False(t, ok, "a lock already held by a different holder must not be acquired")
	assert.False(t, ran, "fn must not run when the lock could not be acquired")
}

// TestRemoteStorageSchedulerLock_ConcurrentRaceIsSerialized_RealServer is the
// concurrency test for the #530 atomicity fix, mirroring
// TestRemoteStorageMachineIdentities_TransitionState_ConcurrentRaceIsSerialized_RealServer's
// style: N goroutines on the SAME downstream (storage.type: remote)
// core.KeyorixCore race to WithSchedulerLock the SAME key concurrently against
// a REAL upstream server (not a mock). Without TryAcquireSchedulerLock's
// single-round-trip atomic conditional write, a naive "check if locked, then
// acquire" pair of separate remote calls would let two racers both observe
// "unlocked" and both proceed to "acquire" — reopening the exact
// double-execution race the lock exists to prevent. This proves fn is never
// observed running on two racers at once, no matter how many concurrently
// attempt to acquire the same key.
func TestRemoteStorageSchedulerLock_ConcurrentRaceIsSerialized_RealServer(t *testing.T) {
	_, downstream := newUpstreamDownstreamForSchedulerLock(t)
	ctx := context.Background()

	const key = 9090
	const racers = 12

	var mu sync.Mutex
	inFlight := false
	var concurrentOverlapDetected atomic.Bool
	var timesRan atomic.Int64

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := downstream.Storage().WithSchedulerLock(ctx, key, func() error {
				mu.Lock()
				if inFlight {
					concurrentOverlapDetected.Store(true)
				}
				inFlight = true
				mu.Unlock()

				// Hold the "lock" for long enough that a broken (non-atomic)
				// implementation racing another goroutine's acquire attempt
				// during this window would very likely both observe
				// "unlocked" and both proceed — giving the race a real chance
				// to manifest rather than being masked by sheer speed.
				time.Sleep(30 * time.Millisecond)

				mu.Lock()
				inFlight = false
				mu.Unlock()
				return nil
			})
			assert.NoError(t, err)
			if ok {
				timesRan.Add(1)
			}
		}()
	}
	close(start) // release all racers at once
	wg.Wait()

	assert.False(t, concurrentOverlapDetected.Load(),
		"fn must never be observed running on two racing WithSchedulerLock callers at the same time")
	assert.GreaterOrEqual(t, timesRan.Load(), int64(1),
		"at least one racer must have won the lock and actually run fn")
}
