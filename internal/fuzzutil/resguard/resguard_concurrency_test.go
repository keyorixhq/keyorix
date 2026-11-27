package resguard

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// Red/green proof for INV-RES-measure-windows-serialized (RESGUARD-PAR-1).

// concSink keeps each goroutine's allocation reachable (one slot per goroutine,
// so the writes do not race) until the test clears it.
var concSink [8][]byte

const concEach = 1 << 20 // what one benign concurrent input allocates

// measureConcurrently runs one Measure per entry of sizes at the same time, each on
// its own Probe (the shape of several fuzz bodies or t.Parallel tests in one
// process). Every fn allocates its size and then sleeps, so without serialisation
// the measured windows overlap and each delta folds in the others' allocations.
func measureConcurrently(t *testing.T, sizes []int) []Cost {
	t.Helper()
	if len(sizes) > len(concSink) {
		t.Fatalf("at most %d concurrent inputs", len(concSink))
	}
	probes := make([]*Probe, len(sizes))
	for i := range probes {
		probes[i] = New(t, Options{SampleEvery: 1})
	}
	costs := make([]Cost, len(sizes))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, size := range sizes {
		wg.Go(func() {
			<-start
			costs[i] = probes[i].Measure(16, func() {
				concSink[i] = make([]byte, size)
				time.Sleep(20 * time.Millisecond)
			})
		})
	}
	close(start)
	wg.Wait()
	clear(concSink[:])
	return costs
}

// TestMeasureConcurrentInputsDoNotPolluteEachOther: eight inputs measured at once,
// each allocating 1 MiB. RED before the process-wide measure lock: the windows
// overlap and an input is charged several MiB it did not allocate. GREEN after:
// each delta is its own 1 MiB plus runtime noise.
func TestMeasureConcurrentInputsDoNotPolluteEachOther(t *testing.T) {
	sizes := make([]int, len(concSink))
	for i := range sizes {
		sizes[i] = concEach
	}
	costs := measureConcurrently(t, sizes)
	for i, c := range costs {
		if !c.AllocSampled {
			t.Fatalf("input %d: alloc not sampled with SampleEvery=1: %+v", i, c)
		}
		if c.AllocBytes < concEach {
			t.Errorf("input %d: alloc_bytes=%d, below its own %d-byte allocation (meter blind)", i, c.AllocBytes, concEach)
		}
		if c.AllocBytes > concEach+concEach/4 {
			t.Errorf("input %d: alloc_bytes=%d for a %d-byte allocation: another input's allocations were charged to it", i, c.AllocBytes, concEach)
		}
	}
}

// TestMeasureConcurrentPlantedBlowUpStillFires is the control for the lock: a
// planted 64 MiB allocation measured concurrently with seven benign inputs must
// still fail a budget calibrated on the benign shape (the lock must not hide a
// real blow-up), and the seven benign inputs must pass it (before the lock they
// false-fire, because the bomb's 64 MiB lands in their windows).
func TestMeasureConcurrentPlantedBlowUpStillFires(t *testing.T) {
	cal := New(t, Options{SampleEvery: 1})
	var seeds []Cost
	for range 8 {
		seeds = append(seeds, cal.Measure(16, func() { allocSink = make([]byte, concEach) }))
	}
	allocSink = nil
	b := Calibrate("concurrency-toy", seeds, DefaultFactor)
	b.KeepOnly("alloc_bytes")
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes not calibrated from %d benign seeds", len(seeds))
	}

	const bomb = 3
	sizes := make([]int, len(concSink))
	for i := range sizes {
		sizes[i] = concEach
	}
	sizes[bomb] = 64 << 20
	costs := measureConcurrently(t, sizes)
	for i, c := range costs {
		var msg string
		fired := b.Check(func(f string, a ...any) { msg = fmt.Sprintf(f, a...) }, c)
		switch {
		case i == bomb && !fired:
			t.Errorf("planted 64 MiB blow-up (input %d, alloc_bytes=%d) did not fire the budget %s", i, c.AllocBytes, b.Summary())
		case i == bomb && !strings.Contains(msg, "alloc_bytes"):
			t.Errorf("blow-up fired but the message does not name the meter: %q", msg)
		case i != bomb && fired:
			t.Errorf("benign input %d false-fired under concurrency: %s", i, msg)
		}
	}
}

// TestMeasureAbandonedWindowDoesNotWedgeLaterInputs: a target that calls Measure
// INSIDE a fuzzutil.Guard closure (the kinopenapi targets) leaves the window held
// when Guard abandons a hung fn. Later inputs in that process (fuzz minimisation
// re-runs candidates there; a plain go test runs later tests there) must neither
// block forever nor be judged on whole-process deltas they share with the hung
// window: they come back WindowShared with the alloc and live-heap meters
// unmeasured, and serialisation resumes once the hung fn returns.
func TestMeasureAbandonedWindowDoesNotWedgeLaterInputs(t *testing.T) {
	old := measureLockWait
	measureLockWait = 50 * time.Millisecond
	defer func() { measureLockWait = old }()

	held, release := make(chan struct{}), make(chan struct{})
	hungDone := make(chan struct{})
	hung := New(t, Options{SampleEvery: 1})
	go func() {
		defer close(hungDone)
		hung.Measure(1, func() { close(held); <-release })
	}()
	<-held
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()

	p := New(t, Options{SampleEvery: 1})
	// Any measured alloc would be over this budget, so a judged input would fire.
	b := Budget{Target: "abandoned-window", Factor: 1, Meters: map[string]MeterBudget{"alloc_bytes": {Floor: 1}}}
	for i := range 2 { // the first waits measureLockWait, the second sees the stuck flag
		got := make(chan Cost, 1)
		go func() { got <- p.Measure(1, func() { allocSink = make([]byte, 1<<16) }) }()
		select {
		case c := <-got:
			if !c.WindowShared || c.AllocSampled || c.Sampled {
				t.Fatalf("input %d beside an abandoned window: want WindowShared and unmeasured alloc/live-heap, got %+v", i, c)
			}
			if b.Check(func(string, ...any) {}, c) {
				t.Fatalf("input %d: an unmeasured alloc meter was judged", i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("input %d wedged behind an abandoned measured window", i)
		}
	}

	close(release)
	released = true
	<-hungDone
	c := p.Measure(1, func() { allocSink = make([]byte, 1<<16) })
	allocSink = nil
	if c.WindowShared || !c.AllocSampled || c.AllocBytes < 1<<16 {
		t.Fatalf("serialisation did not resume after the hung fn returned: %+v", c)
	}
}

// TestMeasureInsideAbandonedGuardDoesNotBlameNextInput is the real kinopenapi
// shape, Guard(Measure(fn)), through the real fuzzutil.Guard: after Guard
// abandons a hung fn that holds the window, the NEXT guarded input must not wait
// on the lock past its own Guard deadline (which would report it as a hang it did
// not cause, and let fuzz minimisation keep a non-reproducing candidate). It must
// return at once, WindowShared, with its alloc and live-heap meters unmeasured.
// measureLockWait keeps its default (2·GuardTimeout taken at package init), so
// only the abandonment signal can make the waiter give up in time.
func TestMeasureInsideAbandonedGuardDoesNotBlameNextInput(t *testing.T) {
	oldTimeout := fuzzutil.GuardTimeout
	fuzzutil.GuardTimeout = 100 * time.Millisecond
	defer func() { fuzzutil.GuardTimeout = oldTimeout }()

	release := make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	p := New(t, Options{SampleEvery: 1})

	var hangMsg string
	fuzzutil.Guard(func(f string, a ...any) { hangMsg = fmt.Sprintf(f, a...) }, "hung input", func() {
		p.Measure(1, func() { <-release })
	})
	if hangMsg == "" {
		t.Fatalf("the hung input was not reported by Guard")
	}

	var nextMsg string
	var c Cost
	fuzzutil.Guard(func(f string, a ...any) { nextMsg = fmt.Sprintf(f, a...) }, "next input", func() {
		c = p.Measure(1, func() { allocSink = make([]byte, 1<<16) })
	})
	allocSink = nil
	if nextMsg != "" {
		t.Fatalf("the input after an abandoned window was blamed for it: %s", nextMsg)
	}
	if !c.WindowShared || c.AllocSampled || c.Sampled {
		t.Fatalf("input beside an abandoned window: want WindowShared and unmeasured alloc/live-heap, got %+v", c)
	}

	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for {
		c = p.Measure(1, func() { allocSink = make([]byte, 1<<16) })
		allocSink = nil
		if !c.WindowShared {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("serialisation did not resume after the hung fn returned")
		}
		time.Sleep(time.Millisecond)
	}
	if !c.AllocSampled || c.AllocBytes < 1<<16 {
		t.Fatalf("resumed input not measured: %+v", c)
	}
}

// TestMeasureEnteredAfterGuardAbandonDoesNotBlameNextInput is the late-entry
// variant (kinopenapi schema_boundedwork parses inside Guard BEFORE Measure): the
// guarded fn overruns its deadline before it reaches Measure, Guard abandons it,
// and only THEN does it take the window and hang. The next guarded input must
// still give up on the lock at once instead of being blamed for the hang.
func TestMeasureEnteredAfterGuardAbandonDoesNotBlameNextInput(t *testing.T) {
	oldTimeout := fuzzutil.GuardTimeout
	fuzzutil.GuardTimeout = 100 * time.Millisecond
	defer func() { fuzzutil.GuardTimeout = oldTimeout }()

	proceed, inWindow, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	released := false
	defer func() {
		if !released {
			close(release)
		}
	}()
	p := New(t, Options{SampleEvery: 1})

	var hangMsg string
	fuzzutil.Guard(func(f string, a ...any) { hangMsg = fmt.Sprintf(f, a...) }, "slow parse then hung visit", func() {
		<-proceed // the "parse" outlives the deadline
		p.Measure(1, func() { close(inWindow); <-release })
	})
	if hangMsg == "" {
		t.Fatalf("the slow input was not reported by Guard")
	}
	close(proceed)
	<-inWindow // the abandoned fn now holds the window

	var nextMsg string
	var c Cost
	fuzzutil.Guard(func(f string, a ...any) { nextMsg = fmt.Sprintf(f, a...) }, "next input", func() {
		c = p.Measure(1, func() { allocSink = make([]byte, 1<<16) })
	})
	allocSink = nil
	if nextMsg != "" {
		t.Fatalf("the input after a late-entered abandoned window was blamed for it: %s", nextMsg)
	}
	if !c.WindowShared || c.AllocSampled {
		t.Fatalf("input beside an abandoned window: want WindowShared and unmeasured alloc, got %+v", c)
	}

	close(release)
	released = true
	deadline := time.Now().Add(5 * time.Second)
	for fuzzutil.AbandonedRunning() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("abandoned-running gauge stuck at %d after the fn returned", fuzzutil.AbandonedRunning())
		}
		time.Sleep(time.Millisecond)
	}
	c = p.Measure(1, func() { allocSink = make([]byte, 1<<16) })
	allocSink = nil
	if c.WindowShared || !c.AllocSampled {
		t.Fatalf("serialisation did not resume: %+v", c)
	}
}
