package core

// last_used_coalescer_stop_race_test.go — the two Stop holes the coordinator
// review of #4344 found (REVFIX-4344-1):
//   - LATE-BACKGROUND: a background flush that passed the stopped check in
//     kick()/onTimer() before Stop latched must not write once Stop has
//     returned, even if it only gets the flush semaphore after Stop's final
//     flush gave up or finished.
//   - WEDGED-IN-FLIGHT: a background flush already inside a (ctx-honouring)
//     write when Stop is called is cancelled by Stop, so Stop's final flush gets
//     the semaphore, writes the stamp, and no flush is still running when Stop
//     returns.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLastUsedCoalescer_StopLateBackgroundFlushDoesNotWrite: the test holds the
// flush semaphore (standing in for a flush in progress) and kick()s, so a
// background flush is past the stopped check and waiting for the semaphore.
// Stop's final flush cannot get it within its ctx and returns. The owner then
// closes the store and the semaphore frees up: the late background flush must
// not write.
func TestLastUsedCoalescer_StopLateBackgroundFlushDoesNotWrite(t *testing.T) {
	w := &closeTrackingWrite{}
	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending)
	a.write = w.hook
	defer stopLastUsedTimerNow(a)

	a.record(lastUsedKey{lastUsedPAT, 1}, time.Now())
	a.flushSem <- struct{}{} // a flush is "running"
	a.kick()                 // background flush past the stopped check
	require.True(t, a.flushing.Load())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	a.Stop(ctx)

	w.closed.Store(true)
	<-a.flushSem // the running flush ends

	require.Eventually(t, func() bool { return !a.flushing.Load() }, 5*time.Second, 5*time.Millisecond,
		"the background flush must end")
	assert.Zero(t, w.afterCloseCount(),
		"a background flush that lost the race to Stop must not write after Stop returned")
}

// TestLastUsedCoalescer_StopCancelsInFlightBackgroundFlush: a background flush is
// inside a slow write that honours its ctx. Stop cancels it instead of waiting
// out lastUsedFlushTimeout, then its own final flush writes the stamp, and no
// flush is left running once Stop returns.
func TestLastUsedCoalescer_StopCancelsInFlightBackgroundFlush(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	entered := make(chan struct{})
	var first sync.Once
	var calls atomic.Int32
	var mu sync.Mutex
	var written []lastUsedKey

	a := newLastUsedCoalescer(time.Hour, lastUsedMaxPending)
	a.write = func(ctx context.Context, k lastUsedKey, _ time.Time) error {
		if calls.Add(1) == 1 {
			first.Do(func() { close(entered) })
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-release:
				return errors.New("db unavailable")
			}
		}
		mu.Lock()
		written = append(written, k)
		mu.Unlock()
		return nil
	}
	defer stopLastUsedTimerNow(a)

	k := lastUsedKey{lastUsedMachineCredential, 3}
	a.record(k, time.Now())
	a.kick()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	a.Stop(ctx)
	elapsed := time.Since(start)

	assert.False(t, a.flushing.Load(), "no background flush may still be running when Stop returns")
	assert.Less(t, elapsed, time.Second, "Stop must cancel the in-flight flush, not wait for its ctx to end")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []lastUsedKey{k}, written, "Stop's final flush must write the stamp the cancelled flush put back")
}
