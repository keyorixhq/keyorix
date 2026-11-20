package resguard

import "fmt"

// Drift watches for a resource that creeps UP across inputs rather than
// spiking on one — the signature of a leak a per-input budget never catches,
// because every single input stays under budget while the floor rises. It
// compares each sampled input's live heap, goroutine count and open-fd count
// against a baseline captured after warm-up, and reports sustained growth (K
// consecutive samples over threshold), naming the meter that crept.
//
// It only consumes SAMPLED costs and watches Cost.LiveHeapAbs (the absolute live
// heap after a forced GC, so transient garbage is already collected — growth seen
// here is live and retained), NOT the per-input Cost.LiveHeap delta: a leak hides
// precisely in the gap between the two, staying invisibly small on every single
// input's delta while the absolute floor climbs. An unsampled Cost is ignored.
type Drift struct {
	warmupLeft int
	haveBase   bool
	baseHeap   uint64
	baseGor    int
	baseFDs    int

	heapRun int
	gorRun  int
	fdRun   int
}

const (
	driftWarmupSamples = 3 // settle the first few sampled inputs before fixing a baseline
	driftK             = 5 // consecutive over-threshold samples before flagging

	driftHeapFactor = 2.0              // heap may double over baseline …
	driftHeapFloor  = 16 * 1024 * 1024 // … plus 16 MiB slack before it counts
	driftGorSlack   = 64               // goroutines over baseline+64
	driftFDSlack    = 64               // fds over baseline+64
)

func newDrift() *Drift { return &Drift{warmupLeft: driftWarmupSamples} }

// Observe folds one sampled Cost into the drift state and returns a non-empty
// reason the moment sustained growth crosses the threshold. The caller fails
// the fuzz iteration on a non-empty return. Unsampled costs are ignored.
func (d *Drift) Observe(c Cost) string {
	if !c.Sampled {
		return ""
	}
	if d.warmupLeft > 0 {
		d.warmupLeft--
		return ""
	}
	if !d.haveBase {
		d.baseHeap, d.baseGor, d.baseFDs = c.LiveHeapAbs, absBaseline(c.Goroutines), absBaseline(c.OpenFDs)
		d.haveBase = true
		return ""
	}

	// Heap: the per-input budget meter rides on the DELTA (Cost.LiveHeap); drift
	// instead rides on the ABSOLUTE live heap (Cost.LiveHeapAbs), because a leak
	// is a floor that creeps up over many inputs — invisible to any single-input
	// delta, which stays small on every one while the absolute climbs.
	heapCeil := uint64(float64(d.baseHeap)*driftHeapFactor) + driftHeapFloor
	if c.LiveHeapAbs > heapCeil {
		d.heapRun++
	} else {
		d.heapRun = 0
	}
	if d.heapRun >= driftK {
		return fmt.Sprintf("DRIFT live-heap: %d bytes for %d consecutive samples, over ceiling %d (baseline %d) — suspected leak",
			c.LiveHeapAbs, d.heapRun, heapCeil, d.baseHeap)
	}

	// Goroutines / fds: the Cost deltas accumulate into an absolute estimate is
	// not reliable, so Drift reads the *delta* sign: a sample whose delta stays
	// positive for K samples is leaking that resource per input.
	d.gorRun = runUp(d.gorRun, c.Goroutines, driftGorSlack)
	if d.gorRun >= driftK {
		return fmt.Sprintf("DRIFT goroutines: +%d per input for %d consecutive samples — goroutine leak", c.Goroutines, d.gorRun)
	}
	d.fdRun = runUp(d.fdRun, c.OpenFDs, driftFDSlack)
	if d.fdRun >= driftK {
		return fmt.Sprintf("DRIFT fds: +%d per input for %d consecutive samples — fd leak", c.OpenFDs, d.fdRun)
	}
	return ""
}

// runUp increments the run when delta exceeds 0 (a per-input net gain), resets
// it otherwise. slack lets a small steady churn (delta <= slack) not count.
func runUp(run, delta, slack int) int {
	if delta > slack {
		return run + 1
	}
	if delta <= 0 {
		return 0
	}
	return run // 0 < delta <= slack: hold, neither grow nor reset
}

func absBaseline(delta int) int {
	if delta < 0 {
		return 0
	}
	return delta
}

// CheckDrift folds c into the Probe's drift watcher; a non-empty return is a
// sustained-growth verdict the harness fails on. Call after Measure.
func (p *Probe) CheckDrift(c Cost) string { return p.drift.Observe(c) }
