package core

// last_used_coalescer_stop_test.go — S3 (key-custody availability): the
// coalescer's lifecycle Stop. Before Stop existed the only shutdown hook was
// FlushLastUsed (= flush), which drains once but leaves the coalescer live: a
// stamp recorded after it re-arms the 30 s timer, which then fires a write
// against a store the caller believed drained/closed, and a failed final flush
// re-arms the timer from finishFlush. The in-repo band-aid for this was the
// hand-rolled stopLastUsedTimerNow helper every coalescer test has to call in
// cleanup "so it cannot fire (and re-arm) against a database the test has
// closed" (last_used_coalescer_overload_test.go). Stop closes the hole.
//
// Oracles here:
//   - RE-ARM-CLOSED (the defect): after the coalescer is stopped, a late stamp
//     must NOT cause any write — in particular not one that lands after the
//     store is "closed". Proven red/green by comparing flush() (re-arms) with
//     Stop() (does not) in the SAME harness.
//   - FINAL-FLUSH-NOT-LOST: Stop performs a final flush, so a pending stamp
//     reaches the store (it is not silently dropped by stopping).
//   - IDEMPOTENT: a second Stop neither panics nor writes again.
//   - BOUNDED: Stop(ctx) returns within ctx even when a background flush is
//     wedged in a stuck write (it does not block forever on the flush sem).
//   - NO TIMER/GOROUTINE RE-ARM: after Stop the timer stays nil across a late
//     record, and no coalescer goroutine is left running.
//
// What these oracles do NOT verify: real Postgres/SQLite close semantics (they
// use an in-memory write hook, so "closed" is a flag, not a torn DB handle);
// that the SERVER's shutdown ordering actually reaches StopLastUsed before any
// real store teardown (covered by reading server/main.go + server/shutdown.go,
// not executed here); and they say nothing about issue (2), the KeyManager
// fsync-under-lock blocking (see keymanager_slow_disk_sync_test.go).

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// closeTrackingWrite is a coalescer write hook that counts writes and flags any
// write that lands while "closed" is set — the shape of a flush touching a store
// the owner has already torn down.
type closeTrackingWrite struct {
	closed     atomic.Bool
	total      atomic.Int32
	mu         sync.Mutex
	afterClose []lastUsedKey
}

func (w *closeTrackingWrite) hook(_ context.Context, k lastUsedKey, _ time.Time) error {
	w.total.Add(1)
	if w.closed.Load() {
		w.mu.Lock()
		w.afterClose = append(w.afterClose, k)
		w.mu.Unlock()
	}
	return nil
}

func (w *closeTrackingWrite) afterCloseCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.afterClose)
}

// TestLastUsedCoalescer_StopVsFlushOnLateStamp is the red/green of the fix in one
// harness. "drain" either flush()es (the old FlushLastUsed behaviour) or Stop()s
// the coalescer; then the owner marks the store closed and a late stamp arrives.
// With flush() the late stamp re-arms the short timer and a write lands after
// close (the defect). With Stop() the late stamp is a no-op and nothing lands
// after close. Same code path, same timings — only the drain differs.
func TestLastUsedCoalescer_StopVsFlushOnLateStamp(t *testing.T) {
	const interval = 15 * time.Millisecond
	cases := []struct {
		name          string
		drain         func(a *lastUsedCoalescer)
		wantAfterZero bool // true: no write may land after close
	}{
		{
			name:          "flush-alone-re-arms (characterises the defect)",
			drain:         func(a *lastUsedCoalescer) { a.flush(context.Background()) },
			wantAfterZero: false,
		},
		{
			name:          "Stop-latches-shut (the fix)",
			drain:         func(a *lastUsedCoalescer) { a.Stop(context.Background()) },
			wantAfterZero: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &closeTrackingWrite{}
			a := newLastUsedCoalescer(interval, lastUsedMaxPending)
			a.write = w.hook
			defer stopLastUsedTimerNow(a) // belt: never leave a timer live past the test

			// A first real use, drained by the hook under test.
			t0 := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
			a.record(lastUsedKey{lastUsedPAT, 1}, t0)
			tc.drain(a)

			// The owner now tears the store down, then a late stamp arrives
			// (an in-flight request finishing after the drain).
			w.closed.Store(true)
			a.record(lastUsedKey{lastUsedPAT, 2}, t0)

			// Give any re-armed timer several intervals to fire.
			deadline := time.After(10 * interval)
			if tc.wantAfterZero {
				<-deadline
				assert.Zero(t, w.afterCloseCount(),
					"Stop must latch the coalescer shut: no write may touch the store after close")
			} else {
				// Confirm the defect actually reproduces here, else the green
				// side proves nothing. Wait until a post-close write appears.
				require.Eventually(t, func() bool { return w.afterCloseCount() > 0 },
					10*interval, interval,
					"expected flush-alone to re-arm the timer and write after close (the gap Stop closes)")
			}
		})
	}
}

// TestLastUsedCoalescer_StopFinalFlushNotLost: Stop drains what is pending, so a
// recorded-but-unflushed stamp reaches the store on an orderly stop (it is not
// silently dropped by stopping).
func TestLastUsedCoalescer_StopFinalFlushNotLost(t *testing.T) {
	var mu sync.Mutex
	written := map[lastUsedKey]time.Time{}
	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending) // long interval: only Stop can flush
	a.write = func(_ context.Context, k lastUsedKey, at time.Time) error {
		mu.Lock()
		written[k] = at
		mu.Unlock()
		return nil
	}
	k := lastUsedKey{lastUsedSession, 7}
	t0 := time.Date(2026, 11, 15, 1, 0, 0, 0, time.UTC)
	a.record(k, t0)
	a.Stop(context.Background())

	mu.Lock()
	got, ok := written[k]
	mu.Unlock()
	require.True(t, ok, "Stop must perform a final flush of the pending stamp")
	assert.True(t, got.Equal(t0))
}

// TestLastUsedCoalescer_StopIdempotent: a second Stop neither panics nor writes
// again, and a record after Stop is a no-op.
func TestLastUsedCoalescer_StopIdempotent(t *testing.T) {
	var writes atomic.Int32
	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending)
	a.write = func(context.Context, lastUsedKey, time.Time) error { writes.Add(1); return nil }

	a.record(lastUsedKey{lastUsedPAT, 1}, time.Now())
	a.Stop(context.Background())
	first := writes.Load()
	require.Equal(t, int32(1), first, "first Stop flushes the one pending stamp")

	require.NotPanics(t, func() { a.Stop(context.Background()) })
	a.record(lastUsedKey{lastUsedPAT, 2}, time.Now()) // dropped: stopped
	a.Stop(context.Background())
	assert.Equal(t, first, writes.Load(), "no write after the first Stop")
	assert.Zero(t, a.pendingLen(), "a stamp recorded after Stop is not queued")
}

// TestLastUsedCoalescer_StopBoundedWhenFlushWedged: a background flush stuck in a
// write must not make Stop block past its context. Stop(ctx) returns when ctx
// ends; it does not wait forever on the flush semaphore the wedged flush holds.
func TestLastUsedCoalescer_StopBoundedWhenFlushWedged(t *testing.T) {
	bw := newBlockedWrite(t, false) // ignores ctx: the write stays wedged until unblock
	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending)
	a.write = bw.write

	// Start a background flush and wait until it is inside the (blocked) write,
	// holding the flush semaphore.
	a.record(lastUsedKey{lastUsedPAT, 1}, time.Now())
	a.kick()
	<-bw.entered

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	start := time.Now()
	go func() { a.Stop(ctx); close(done) }()
	select {
	case <-done:
		elapsed := time.Since(start)
		assert.Less(t, elapsed, 3*time.Second,
			"Stop must give up on ctx (~100ms), not block on the wedged flush")
	case <-time.After(3 * time.Second):
		t.Fatal("Stop blocked > 3s behind a wedged background flush — not bounded by ctx")
	}
	bw.unblock() // let the wedged background flush finish so it does not leak (also in cleanup)
}

// TestLastUsedCoalescer_StopNoReArmNoLeak: after Stop the timer stays nil across a
// late record, and no coalescer goroutine is left running.
func TestLastUsedCoalescer_StopNoReArmNoLeak(t *testing.T) {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	before := runtime.NumGoroutine()
	a := newLastUsedCoalescer(10*time.Millisecond, lastUsedMaxPending)
	a.write = func(context.Context, lastUsedKey, time.Time) error { return nil }

	a.record(lastUsedKey{lastUsedSession, 1}, time.Now()) // arms the timer
	a.Stop(context.Background())

	a.mu.Lock()
	require.True(t, a.stopped)
	require.Nil(t, a.timer, "Stop clears the timer")
	a.mu.Unlock()

	a.record(lastUsedKey{lastUsedSession, 2}, time.Now()) // must not re-arm
	time.Sleep(50 * time.Millisecond)
	a.mu.Lock()
	armed := a.timer != nil
	a.mu.Unlock()
	assert.False(t, armed, "a record after Stop must not re-arm the timer")

	runtime.GC()
	time.Sleep(20 * time.Millisecond)
	after := runtime.NumGoroutine()
	assert.LessOrEqual(t, after, before+1,
		"Stop must leave no coalescer goroutine running (before=%d after=%d)", before, after)
}
