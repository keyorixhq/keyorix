package libconformance

import (
	"os"
	"testing"

	"github.com/digitorus/timestamp"

	"github.com/keyorixhq/keyorix/internal/fuzzutil/resguard"
)

// TestDigitorusTimestampRoundTripRedGreen is the committed red/green proof for oracle TS-2.
//
// GREEN: a well-formed request round-trips through the REAL Marshal — marshal∘parse is a fixed
// point, so the oracle does not fire on correct behaviour.
// RED: a non-idempotent marshaller (real Marshal + a trailing byte) breaks the fixed point —
// the re-marshalled form is either not re-parseable or differs on the second marshal — and the
// oracle reports a finding. This proves the TS-2 comparator detects a request codec whose
// re-serialisation is not stable.
func TestDigitorusTimestampRoundTripRedGreen(t *testing.T) {
	seeds := validRequestSeeds(t)
	if len(seeds) == 0 {
		t.Fatal("precondition: CreateRequest must produce at least one valid request seed")
	}
	good := seeds[0]

	// GREEN: real Marshal is a fixed point.
	finding, exercised := requestRoundTrip(good, (*timestamp.Request).Marshal)
	if !exercised {
		t.Fatalf("GREEN precondition: a valid request must exercise the round-trip (ParseRequest rejected it)")
	}
	if finding != "" {
		t.Fatalf("GREEN: a valid request must round-trip cleanly, got: %s", finding)
	}

	// RED: a marshaller that appends a trailing byte is not idempotent under parse.
	badMarshal := func(r *timestamp.Request) ([]byte, error) {
		b, err := r.Marshal()
		if err != nil {
			return nil, err
		}
		return append(b, 0x00), nil
	}
	redFinding, redExercised := requestRoundTrip(good, badMarshal)
	if !redExercised {
		t.Fatalf("RED precondition: the round-trip must run")
	}
	if redFinding == "" {
		t.Fatalf("RED: a non-idempotent marshaller was expected to be caught, but no finding was reported")
	}
	t.Logf("RED fired as expected: %s", redFinding)
}

// calibrateDigitorusTimestamp derives the resource budget from the valid-request corpus, each
// driven through ParseResponse (the hostile sink the budget guards), with the per-byte slope
// (a parser whose work scales with input, not a decompression target).
func calibrateDigitorusTimestamp(tb testing.TB) resguard.Budget {
	tb.Helper()
	seeds := validRequestSeeds(tb)
	// Add a couple of small benign DER shapes so the floor is not calibrated off requests alone.
	seeds = append(seeds, []byte{0x30, 0x03, 0x02, 0x01, 0x01}, []byte{0x30, 0x80, 0x00, 0x00})
	var costs []resguard.Cost
	for range 8 { // repeat to average GC/alloc noise into the p99
		for _, s := range seeds {
			p := resguard.New(tb, resguard.Options{SampleEvery: 1})
			costs = append(costs, p.Measure(len(s), func() {
				_, _ = timestamp.ParseResponse(s)
			}))
		}
	}
	return resguard.Calibrate("digitorus_timestamp", costs, resguard.DefaultFactor)
}

// TestResguardDigitorusTimestampCalibrate regenerates the committed budget when
// RESGUARD_CALIBRATE=1; otherwise it asserts calibration produces an alloc budget.
func TestResguardDigitorusTimestampCalibrate(t *testing.T) {
	b := calibrateDigitorusTimestamp(t)
	if _, ok := b.Meters["alloc_bytes"]; !ok {
		t.Fatalf("alloc_bytes should be calibrated; meters=%v", b.Summary())
	}
	if os.Getenv("RESGUARD_CALIBRATE") == "1" {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := b.WriteJSON(digitorusTimestampBudgetPath); err != nil {
			t.Fatalf("write budget: %v", err)
		}
		t.Logf("wrote %s: %s", digitorusTimestampBudgetPath, b.Summary())
	}
}

// TestResguardDigitorusTimestampBudgetRedGreen proves the resguard budget is attached and
// load-bearing in the fuzz body: a benign ParseResponse stays under budget (GREEN) and a
// synthetic Cost an order of magnitude over the alloc ceiling trips Check (RED). A deterministic
// ASN.1 input that amplifies alloc 10x over a benign one is not readily constructible here; the
// amplification-shape detection is proven in resguard's own package tests. This test proves the
// wiring fires.
func TestResguardDigitorusTimestampBudgetRedGreen(t *testing.T) {
	b, err := resguard.LoadBudget(digitorusTimestampBudgetPath)
	if err != nil {
		t.Skipf("no committed budget (%v); run calibrate first", err)
	}
	seeds := validRequestSeeds(t)
	if len(seeds) == 0 {
		t.Fatal("precondition: need a valid request seed")
	}
	good := seeds[0]

	// GREEN
	p := resguard.New(t, resguard.Options{SampleEvery: 1})
	green := p.Measure(len(good), func() { _, _ = timestamp.ParseResponse(good) })
	if b.Check(func(string, ...any) {}, green) {
		t.Fatalf("GREEN: benign ParseResponse (alloc=%d for %d bytes) must not trip the budget", green.AllocBytes, len(good))
	}

	// RED: synthetic Cost 10x over the alloc ceiling.
	mb := b.Meters["alloc_bytes"]
	ceiling := b.Factor * (mb.Floor + mb.PerByte*float64(len(good)))
	over := uint64(ceiling*10) + 1
	red := resguard.Cost{InputLen: len(good), Sampled: true, AllocBytes: over}
	if !b.Check(func(string, ...any) {}, red) {
		t.Fatalf("RED: a Cost with alloc=%d (10x over budget) must trip Check", over)
	}
}
