package hostile

import (
	"sync/atomic"
	"time"
)

// bounder is the subset of testing.TB that WaitBounded needs, so the classification
// logic can be tested with a recording fake (a real *testing.T would fail the test).
type bounder interface {
	Helper()
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

// heartbeatInterval is how often the liveness goroutine ticks. A frozen process (GC
// stall, swap, cgroup throttle, host contention) shows up as a gap between ticks that is
// far larger than this.
const heartbeatInterval = 50 * time.Millisecond

// WaitBounded is the bounded-time oracle shared by the hostile-server harnesses: it waits
// for done to close for at most limit and reports a violation otherwise — but it first
// asks whether the DRIVER hung or the whole PROCESS was frozen.
//
// A heartbeat goroutine ticks every heartbeatInterval and records the largest gap. If the
// deadline passes and the heartbeat itself was frozen for at least limit/3, the process
// was not scheduled for a long stretch (seen on the vCD fuzz boxes: execs/sec stuck at 0
// for 12+ s, then a "driver did not return" finding that never reproduces). The call is
// then given ONE more full limit after the process recovers: a call that returns in that
// grace was a stall artifact (logged as STALL, not a failure); a call that still has not
// returned is a real hang and fails, with the heartbeat gap in the message.
//
// It does not hide hangs: a driver blocked while the process runs normally has a healthy
// heartbeat and fails at the first deadline, exactly as before. It does not distinguish a
// hang that ALSO freezes the process (e.g. unbounded allocation driving GC thrash) from an
// environmental stall until the grace expires — in that case the call stays unreturned
// and the finding is reported, one limit later.
func WaitBounded(tb bounder, done <-chan struct{}, limit time.Duration, msg string) {
	tb.Helper()
	var maxGap atomic.Int64
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		last := time.Now()
		t := time.NewTicker(heartbeatInterval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				if g := int64(now.Sub(last)); g > maxGap.Load() {
					maxGap.Store(g)
				}
				last = now
			}
		}
	}()
	waitBounded(tb, done, limit, msg, func() time.Duration { return time.Duration(maxGap.Load()) })
}

// waitBounded is WaitBounded with the heartbeat reading injected, so the classification
// can be exercised deterministically.
func waitBounded(tb bounder, done <-chan struct{}, limit time.Duration, msg string, gap func() time.Duration) {
	tb.Helper()
	select {
	case <-done:
		return
	case <-time.After(limit):
	}
	g := gap()
	if g < limit/3 {
		tb.Errorf("%s (heartbeat healthy: max gap %s, process was running — driver hang)", msg, g.Round(time.Millisecond))
		return
	}
	select {
	case <-done:
		tb.Logf("STALL: process frozen for %s of the %s budget; the call returned in the grace period, so this is not a driver hang", g.Round(time.Millisecond), limit)
	case <-time.After(limit):
		tb.Errorf("%s (process stalled %s, and the call still had not returned after a further %s — hang)", msg, g.Round(time.Millisecond), limit)
	}
}
