package resguard

import (
	"sync/atomic"
	"time"
)

// SleepClock is the virtual-time seam. Code under test that asks to sleep /
// back off through this clock has its requested durations SUMMED here instead
// of actually sleeping, so a fake clock cannot hide an unbounded backoff: an
// Azure RetryDelay -1 class bug (a negative or gigantic retry delay turned into
// a huge sleep) shows up as a large Cost.Sleep even though the test finished
// instantly.
//
// It meters only sleeps routed through it — a target must inject SleepClock
// where production injects its clock. Code that calls time.Sleep directly is
// invisible to this meter (and, if it sleeps for real, is caught by
// fuzzutil.Guard's wall-clock deadline instead). Both facts are stated so the
// meter is never mistaken for a total sleep accountant.
type SleepClock struct {
	total atomic.Int64 // nanoseconds requested since reset
	count atomic.Int64
}

// NewSleepClock returns a clock that accumulates requested sleeps without ever
// blocking.
func NewSleepClock() *SleepClock { return &SleepClock{} }

// Sleep records d (clamped at zero for a negative duration, which is itself the
// bug shape: a negative RetryDelay must not silently become "no wait") and
// returns immediately.
func (c *SleepClock) Sleep(d time.Duration) {
	if d < 0 {
		// A negative request is a defect signal: record its magnitude so the
		// meter still sees "the code wanted to wait a nonsense amount".
		d = -d
	}
	c.total.Add(int64(d))
	c.count.Add(1)
}

// After is a time.After-shaped helper that returns an already-fired channel
// after recording d, so select-on-timer backoff loops run at full speed while
// their requested delay is still metered.
func (c *SleepClock) After(d time.Duration) <-chan time.Time {
	c.Sleep(d)
	ch := make(chan time.Time, 1)
	ch <- time.Unix(0, c.total.Load())
	return ch
}

func (c *SleepClock) reset() { c.total.Store(0); c.count.Store(0) }

// Total is the summed requested sleep since the last reset.
func (c *SleepClock) Total() time.Duration { return time.Duration(c.total.Load()) }

// Count is the number of sleep requests since the last reset.
func (c *SleepClock) Count() int { return int(c.count.Load()) }
