package fuzzutil

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// StallLogEnv optionally names a file to which every detected freeze is appended (one line:
// UTC time, pid, executable, frozen duration). It exists to measure how often and how long
// the fuzz boxes freeze, so a finding that never reproduces can be matched against it.
const StallLogEnv = "FUZZ_STALL_LOG"

// A wall-clock "did not return within N" oracle cannot tell a hung call from a process
// that simply was not scheduled for a while (GC/swap/cgroup throttle/host contention on
// the shared fuzz boxes: execs/sec stuck at 0 for 12+ s, then a "hang" finding that never
// reproduces — FuzzPgxCopyResponse cba59eeb6c4b, FuzzMySQLResponseMixing 5b1a9a645232).
//
// The stall monitor is ONE goroutine per process that ticks every stallTick and records
// each gap between ticks longer than stallFloor. Oracles ask frozenSince(start): how much
// of [start, now] the process spent frozen. A deadline miss with a mostly-running process
// fails exactly as before; a deadline miss with a large frozen share gets ONE more full
// limit after the process recovers, and only a call still unreturned then is a failure.
// Hot paths pay nothing: the monitor is only read on the (rare) deadline-miss path.

const (
	stallTick  = 50 * time.Millisecond
	stallFloor = 500 * time.Millisecond // gaps below this are ordinary scheduling jitter
	stallRing  = 32
)

type stallGap struct{ from, to time.Duration } // offsets from stallBase

var (
	stallOnce sync.Once
	stallBase time.Time
	stallLast atomic.Int64 // offset of the latest tick from stallBase, ns
	stallMu   sync.Mutex
	stallGaps [stallRing]stallGap
	stallN    int

	// StallsRecovered counts deadline misses that were reclassified as a frozen process
	// because the call returned inside the grace period. Exposed so a rig can log it.
	StallsRecovered atomic.Int64
)

// startStallMonitor starts the monitor once. Oracles call it BEFORE the guarded call so
// the history already covers the call window.
func startStallMonitor() {
	stallOnce.Do(func() {
		stallBase = time.Now()
		go func() {
			t := time.NewTicker(stallTick)
			defer t.Stop()
			last := time.Duration(0)
			for now := range t.C {
				off := now.Sub(stallBase)
				if off-last > stallFloor {
					stallMu.Lock()
					stallGaps[stallN%stallRing] = stallGap{last, off}
					stallN++
					stallMu.Unlock()
					logStall(off - last)
				}
				stallLast.Store(int64(off))
				last = off
			}
		}()
	})
}

// logStall appends one line to $FUZZ_STALL_LOG when it is set. Best effort: a short O_APPEND
// write, errors ignored, so instrumentation can never fail a fuzz run.
func logStall(frozen time.Duration) {
	path := os.Getenv(StallLogEnv)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- operator-set test-rig log path, never reachable from fuzz input
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s pid=%d exe=%s frozen=%s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), filepath.Base(os.Args[0]), frozen.Round(time.Millisecond))
}

// EffectiveElapsed is time.Since(start) minus the time the process spent frozen inside that
// window: the right number for an `elapsed > ceiling` oracle, which would otherwise fire on a
// freeze that no code under test caused. frozen is returned so a failure message can show it.
func EffectiveElapsed(start time.Time) (effective, frozen time.Duration) {
	total := time.Since(start)
	frozen = frozenSinceFn(start)
	frozen = min(frozen, total)
	return total - frozen, frozen
}

// frozenSinceFn is frozenSince behind a variable so tests can inject a freeze.
var frozenSinceFn = frozenSince

// frozenSince returns how long, within [start, now], the process was frozen: recorded
// gaps overlapping the window plus the still-open gap since the latest tick.
func frozenSince(start time.Time) time.Duration {
	startStallMonitor()
	s := start.Sub(stallBase)
	now := time.Since(stallBase)
	overlap := func(a, b time.Duration) time.Duration {
		if a < s {
			a = s
		}
		if b > now {
			b = now
		}
		if b > a {
			return b - a
		}
		return 0
	}
	var total time.Duration
	stallMu.Lock()
	n := min(stallN, stallRing)
	for i := range n {
		total += overlap(stallGaps[i].from, stallGaps[i].to)
	}
	stallMu.Unlock()
	if open := now - time.Duration(stallLast.Load()); open > stallFloor {
		total += overlap(time.Duration(stallLast.Load()), now)
	}
	return total
}

// Wait waits for a value on ch for at most limit and reports whether it arrived.
// ok is false only after the stall classification above: either the process was running
// (first deadline) or the call stayed unreturned for a further full limit after a freeze.
// frozen is the freeze time observed inside the first window (0 when none).
func Wait[T any](ch <-chan T, limit time.Duration) (v T, ok bool, frozen time.Duration) {
	startStallMonitor()
	return wait(ch, limit, time.Now(), frozenSinceFn)
}

func wait[T any](ch <-chan T, limit time.Duration, start time.Time, frozenFn func(time.Time) time.Duration) (v T, ok bool, frozen time.Duration) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case v = <-ch:
		return v, true, 0
	case <-timer.C:
	}
	frozen = frozenFn(start)
	if frozen < limit/3 {
		return v, false, frozen
	}
	grace := time.NewTimer(limit)
	defer grace.Stop()
	select {
	case v = <-ch:
		StallsRecovered.Add(1)
		return v, true, frozen
	case <-grace.C:
		return v, false, frozen
	}
}

// bounder is the subset of testing.TB that WaitBounded needs (a fake can record).
type bounder interface {
	Helper()
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

// WaitBounded is the shared "driver call must return" oracle for harnesses that hold a
// done channel: it reports a violation through tb only when Wait says so, naming the
// freeze time so a reader can see whether the process was running.
func WaitBounded(tb bounder, done <-chan struct{}, limit time.Duration, msg string) {
	tb.Helper()
	_, ok, frozen := Wait(done, limit)
	switch {
	case ok && frozen > 0:
		tb.Logf("STALL: process frozen for %s of the %s budget; the call returned in the grace period, so this is not a driver hang", frozen.Round(time.Millisecond), limit)
	case !ok && frozen >= limit/3:
		tb.Errorf("%s (process was frozen %s, and the call still had not returned after a further %s — hang)", msg, frozen.Round(time.Millisecond), limit)
	case !ok:
		tb.Errorf("%s (process was running: frozen %s of %s — driver hang)", msg, frozen.Round(time.Millisecond), limit)
	}
}
