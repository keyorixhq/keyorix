package resguard

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// slowPromoSink defeats dead-code elimination so the test allocations happen.
var slowPromoSink []byte

// TestMeasureSlowPromotionDoesNotFakeAlloc guards INV-RES-sampled-meters-skip-cheap-inputs
// for the slow-wall promotion. An input off the SampleEvery cadence runs fn
// without complexity.Measure, so its AllocBytes/Mallocs are a structural zero even
// when SlowWall promotes it to Sampled. That zero must never be used as an alloc
// measurement: if it were, a calibration corpus with slow inputs would read the
// alloc meters as "never fired" and drop them, and a 64 MiB alloc on a later,
// genuinely alloc-measured input would pass with no ceiling at all.
//
// The slow input is a real Probe measurement (input #1 of a SampleEvery-1000
// probe, 64 x 1 MiB allocated, then a sleep past SlowWall); it is repeated in the
// corpus so that, if its zero is counted, it outweighs the one on-cadence seed at
// p99.
func TestMeasureSlowPromotionDoesNotFakeAlloc(t *testing.T) {
	p := New(t, Options{SampleEvery: 1000, SlowWall: 50 * time.Millisecond})
	// Input #0 is on the cadence: complexity.Measure runs and sees the 4 KiB.
	seed := p.Measure(16, func() { slowPromoSink = make([]byte, 4<<10) })
	// Input #1 is off the cadence and only promoted because it was slow.
	slow := p.Measure(16, func() {
		for range 64 {
			slowPromoSink = make([]byte, 1<<20)
		}
		time.Sleep(150 * time.Millisecond)
	})
	if !slow.Sampled {
		t.Fatalf("precondition: a %s input over SlowWall must be promoted to Sampled", slow.Wall)
	}
	if seed.AllocBytes < 4<<10 {
		t.Fatalf("precondition: the on-cadence seed must measure its 4 KiB alloc, got %d", seed.AllocBytes)
	}

	corpus := []Cost{seed}
	for range 100 {
		corpus = append(corpus, slow)
	}
	b := Calibrate("slowpromo", corpus, DefaultFactor)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Errorf("alloc_bytes budget missing: the slow input's unmeasured zero was folded into the alloc p99 (budget %s)", b.Summary())
	}

	// A 64 MiB allocation on an input whose alloc WAS measured must fail a budget
	// calibrated from a 4 KiB seed.
	big := New(t, Options{SampleEvery: 1}).Measure(16, func() {
		for range 64 {
			slowPromoSink = make([]byte, 1<<20)
		}
	})
	if big.AllocBytes < 64<<20 {
		t.Fatalf("precondition: an on-cadence input must measure its 64 MiB alloc, got %d", big.AllocBytes)
	}
	var msg string
	if !b.Check(func(format string, args ...any) { msg = fmt.Sprintf(format, args...) }, big) {
		t.Fatalf("false green: a 64 MiB alloc on an alloc-measured input passed a budget calibrated from a 4 KiB seed")
	}
	if !strings.Contains(msg, "alloc_bytes=") {
		t.Fatalf("budget fired, but not on alloc_bytes: %s", msg)
	}
}
