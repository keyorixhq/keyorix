package fuzzutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/metrics"
	"sync"
	"sync/atomic"
	"time"
)

// StallLogEnv optionally names a file to which every detected freeze is appended (one line:
// UTC time, pid, executable, frozen duration). It exists to measure how often and how long
// the fuzz boxes freeze, so a finding that never reproduces can be matched against it.
// Every deadline miss the oracles below excuse as a freeze is appended there too.
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
//
// A freeze the INPUT caused is not forgiven. A memory or decompression bomb makes the
// process thrash in GC or swap, which looks exactly like a host freeze to the tick monitor.
// The monitor therefore also samples the runtime's cumulative heap-allocation and GC-CPU
// counters on every tick, and selfCausedFreeze refuses the grace when the window shows heap
// or GC growth (selfFreezeAllocBytes, selfFreezeGCShare). A host freeze runs no Go code, so
// it grows neither. The grace also forgives only the frozen time: a call that returns in
// the grace period but ran (wall minus freeze) longer than the limit still fails.

const (
	stallTick  = 50 * time.Millisecond
	stallFloor = 500 * time.Millisecond // gaps below this are ordinary scheduling jitter
	stallRing  = 32

	// heapRing holds the per-tick counter samples: 2048 ticks is ~100 s, longer than any
	// guarded window. A window older than the ring is measured from the oldest sample,
	// which can only overstate the growth (the check then refuses the grace: fails closed).
	heapRing = 2048
	// selfFreezeAllocBytes: heap allocated inside the window at or above which a freeze is
	// blamed on the input. Fuzz inputs here are capped at 64 KiB; 64 MiB is a 1000x
	// amplification, far beyond any parser's legitimate work on one input.
	selfFreezeAllocBytes = 64 << 20
	// selfFreezeGCShare: GC CPU inside the window at or above frozen/selfFreezeGCShare
	// blames the freeze on the input (a heap near its limit thrashes in GC without
	// necessarily allocating much new memory).
	selfFreezeGCShare = 4
)

type stallGap struct{ from, to time.Duration } // offsets from stallBase

// heapSample is one reading of the runtime counters selfCausedFreeze compares.
type heapSample struct {
	off    time.Duration // offset from stallBase
	allocs uint64        // /gc/heap/allocs:bytes, cumulative
	gcCPU  float64       // /cpu/classes/gc/total:cpu-seconds, cumulative
}

var (
	stallOnce sync.Once
	stallBase time.Time
	stallLast atomic.Int64 // offset of the latest tick from stallBase, ns
	stallMu   sync.Mutex
	stallGaps [stallRing]stallGap
	stallN    int

	heapMu    sync.Mutex
	heapSamps [heapRing]heapSample
	heapN     int

	// StallsRecovered counts deadline misses that were reclassified as a frozen process
	// because the call returned inside the grace period. Exposed so a rig can log it.
	StallsRecovered atomic.Int64
)

// startStallMonitor starts the monitor once. Oracles call it BEFORE the guarded call so
// the history already covers the call window.
func startStallMonitor() {
	stallOnce.Do(func() {
		stallBase = time.Now()
		samples := newHeapSamples()
		recordHeap(readHeap(samples, 0)) // a baseline for windows that start right away
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
				recordHeap(readHeap(samples, off))
				stallLast.Store(int64(off))
				last = off
			}
		}()
	})
}

func newHeapSamples() []metrics.Sample {
	return []metrics.Sample{{Name: "/gc/heap/allocs:bytes"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}}
}

func readHeap(samples []metrics.Sample, off time.Duration) heapSample {
	metrics.Read(samples)
	h := heapSample{off: off}
	if samples[0].Value.Kind() == metrics.KindUint64 {
		h.allocs = samples[0].Value.Uint64()
	}
	if samples[1].Value.Kind() == metrics.KindFloat64 {
		h.gcCPU = samples[1].Value.Float64()
	}
	return h
}

func recordHeap(h heapSample) {
	heapMu.Lock()
	heapSamps[heapN%heapRing] = h
	heapN++
	heapMu.Unlock()
}

// heapAt returns the newest sample taken at or before offset s, or the oldest sample kept
// when none is that old (overstating the growth, never understating it).
func heapAt(s time.Duration) heapSample {
	heapMu.Lock()
	defer heapMu.Unlock()
	n := min(heapN, heapRing)
	oldest := heapSamps[(heapN-n)%heapRing]
	for i := heapN - 1; i >= heapN-n; i-- {
		if h := heapSamps[i%heapRing]; h.off <= s {
			return h
		}
	}
	return oldest
}

// selfCausedFreeze reports whether a freeze of the given length inside [start, now] is the
// input's own doing: heap allocation in the window of at least selfFreezeAllocBytes, or GC
// CPU of at least frozen/selfFreezeGCShare. sig names the measured growth for messages.
// It is read only on the deadline-miss path.
func selfCausedFreeze(start time.Time, frozen time.Duration) (self bool, sig string) {
	startStallMonitor()
	base := heapAt(start.Sub(stallBase))
	now := readHeap(newHeapSamples(), time.Since(stallBase))
	var allocs uint64
	if now.allocs > base.allocs {
		allocs = now.allocs - base.allocs
	}
	gc := time.Duration((now.gcCPU - base.gcCPU) * float64(time.Second))
	sig = fmt.Sprintf("heap allocs +%d MiB, GC CPU %s in the window", allocs>>20, gc.Round(time.Millisecond))
	return allocs >= selfFreezeAllocBytes || gc >= frozen/selfFreezeGCShare, sig
}

// selfCausedFn is selfCausedFreeze behind a variable so tests can inject a verdict.
var selfCausedFn = selfCausedFreeze

// logStall appends one line to $FUZZ_STALL_LOG when it is set. Best effort: a short O_APPEND
// write, errors ignored, so instrumentation can never fail a fuzz run.
func logStall(frozen time.Duration) {
	appendStallLog(fmt.Sprintf("frozen=%s", frozen.Round(time.Millisecond)))
}

func appendStallLog(detail string) {
	path := os.Getenv(StallLogEnv)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 G703 -- operator-set test-rig log path, never reachable from fuzz input
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "%s pid=%d exe=%s %s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), filepath.Base(os.Args[0]), detail)
}

// noteExcused records a deadline miss that an oracle forgave as a frozen process: one line
// on stderr (so the fuzz log shows it next to the run) and one in $FUZZ_STALL_LOG.
func noteExcused(what string, limit, elapsed, frozen time.Duration, sig string) {
	line := fmt.Sprintf("excused=%q limit=%s elapsed=%s frozen=%s (%s)", what, limit, elapsed.Round(time.Millisecond), frozen.Round(time.Millisecond), sig)
	_, _ = fmt.Fprintf(os.Stderr, "fuzzutil: STALL: deadline miss excused as a frozen process: %s\n", line)
	appendStallLog(line)
}

// OverDeadline is the bounded-work oracle "the call that started at start must finish
// within deadline", for harnesses that time a synchronous call. over is true when
//   - the wall time exceeds 2x deadline: a hard ceiling no freeze can excuse;
//   - the process was running (wall minus observed freeze) for longer than deadline; or
//   - the wall time exceeds deadline and the freeze in the window was the input's own
//     doing (selfCausedFreeze), so none of it is forgiven.
//
// why describes the verdict with its numbers, for the failure message. A call within the
// deadline returns at once without reading the monitor; an excused miss is logged
// (noteExcused) and counted in StallsRecovered.
func OverDeadline(start time.Time, deadline time.Duration) (over bool, why string) {
	raw := time.Since(start)
	if raw <= deadline {
		return false, ""
	}
	frozen := min(frozenSinceFn(start), raw)
	switch {
	case raw > 2*deadline:
		return true, fmt.Sprintf("took %s wall, over the 2x ceiling of the %s deadline (process frozen %s)", raw.Round(time.Millisecond), deadline, frozen.Round(time.Millisecond))
	case raw-frozen > deadline:
		return true, fmt.Sprintf("took %s (> %s) with the process running for %s of it (frozen %s)", raw.Round(time.Millisecond), deadline, (raw - frozen).Round(time.Millisecond), frozen.Round(time.Millisecond))
	}
	self, sig := selfCausedFn(start, frozen)
	if self {
		return true, fmt.Sprintf("took %s (> %s); the process froze for %s but the input caused it (%s)", raw.Round(time.Millisecond), deadline, frozen.Round(time.Millisecond), sig)
	}
	StallsRecovered.Add(1)
	noteExcused("bounded-work deadline", deadline, raw, frozen, sig)
	return false, ""
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
	if last := time.Duration(stallLast.Load()); now-last > stallFloor {
		total += overlap(last, now)
	}
	return total
}

// graceFor decides, at a deadline miss, whether the call gets the one extra limit: only
// when a third or more of the window was a freeze and the input did not cause it. why
// explains a refusal; sig is the measured growth when the check ran.
func graceFor(start time.Time, limit, frozen time.Duration) (grace bool, why string) {
	if frozen < limit/3 {
		return false, "process was running"
	}
	if self, sig := selfCausedFn(start, frozen); self {
		return false, "freeze was self-inflicted: " + sig
	}
	return true, ""
}

// settle re-checks a call that returned in the grace period over the whole window: only
// frozen time is forgiven, so the running time must still fit the limit, and a freeze the
// input caused during the grace is not forgiven either.
func settle(start time.Time, limit time.Duration, frozenFn func(time.Time) time.Duration) (ok bool, elapsed, frozen time.Duration, why string) {
	elapsed = time.Since(start)
	frozen = min(frozenFn(start), elapsed)
	if run := elapsed - frozen; run > limit {
		return false, elapsed, frozen, fmt.Sprintf("returned after %s but ran %s of it, over the %s limit", elapsed.Round(time.Millisecond), run.Round(time.Millisecond), limit)
	}
	self, sig := selfCausedFn(start, frozen)
	if self {
		return false, elapsed, frozen, "freeze was self-inflicted: " + sig
	}
	return true, elapsed, frozen, sig
}

// Wait waits for a value on ch for at most limit and reports whether it arrived.
// ok is false only after the stall classification above: the process was running at the
// first deadline, the freeze was self-inflicted, the call stayed unreturned for a further
// full limit, or it returned in the grace period after running longer than limit.
// frozen is the freeze time observed in the window (0 when the call met the deadline).
func Wait[T any](ch <-chan T, limit time.Duration) (v T, ok bool, frozen time.Duration) {
	startStallMonitor()
	v, ok, frozen, _ = wait(ch, limit, time.Now(), frozenSinceFn)
	return v, ok, frozen
}

// wait is Wait plus why, the reason for a false ok (WaitBounded puts it in its message).
func wait[T any](ch <-chan T, limit time.Duration, start time.Time, frozenFn func(time.Time) time.Duration) (v T, ok bool, frozen time.Duration, why string) {
	timer := time.NewTimer(limit)
	defer timer.Stop()
	select {
	case v = <-ch:
		return v, true, 0, ""
	case <-timer.C:
	}
	frozen = min(frozenFn(start), time.Since(start))
	if grace, why := graceFor(start, limit, frozen); !grace {
		return v, false, frozen, why
	}
	g := time.NewTimer(limit)
	defer g.Stop()
	select {
	case v = <-ch:
	case <-g.C:
		return v, false, frozen, fmt.Sprintf("process was frozen %s, and the call still had not returned after a further %s", frozen.Round(time.Millisecond), limit)
	}
	ok, elapsed, frozen, why := settle(start, limit, frozenFn)
	if !ok {
		return v, false, frozen, why
	}
	StallsRecovered.Add(1)
	noteExcused("wait", limit, elapsed, frozen, why)
	return v, true, frozen, ""
}

// bounder is the subset of testing.TB that WaitBounded needs (a fake can record).
type bounder interface {
	Helper()
	Errorf(format string, args ...any)
	Logf(format string, args ...any)
}

// WaitBounded is the shared "driver call must return" oracle for harnesses that hold a
// done channel: it reports a violation through tb only when Wait says so, naming the
// freeze time and the reason so a reader can see whether the process was running.
func WaitBounded(tb bounder, done <-chan struct{}, limit time.Duration, msg string) {
	tb.Helper()
	startStallMonitor()
	_, ok, frozen, why := wait(done, limit, time.Now(), frozenSinceFn)
	switch {
	case ok && frozen > 0:
		tb.Logf("STALL: process frozen for %s of the %s budget; the call returned in the grace period, so this is not a driver hang", frozen.Round(time.Millisecond), limit)
	case !ok && frozen >= limit/3:
		tb.Errorf("%s (%s; not excused as a frozen process)", msg, why)
	case !ok:
		tb.Errorf("%s (process was running: frozen %s of %s — driver hang)", msg, frozen.Round(time.Millisecond), limit)
	}
}
