package resguard

import (
	"os"
	"testing"
)

// Cost-guided fuzzing A/B demonstration (PerfFuzz idea on the stock
// `go test -fuzz` engine).
//
// toyWork maps an input to a "size" n by SUMMING its bytes, then allocates a
// buffer proportional to n. Crucially there is NO new code edge as n grows (one
// loop, one make) until n crosses amplifyThreshold. So the stock
// coverage-guided engine, which only keeps an input when it reaches a NEW EDGE,
// has no gradient to climb toward larger n — it mutates blind. FeedCoverage
// turns each larger allocation bucket into a new edge, giving the engine a
// gradient it will climb straight to the amplifier.
//
// FuzzToyAmplifyBuckets calls FeedCoverage; FuzzToyAmplifyNoBuckets does not.
// With KEYORIX_RESGUARD_TOY_AB=1 both fail (t.Fatalf) the instant n reaches
// amplifyThreshold, so "wall time to failure" is "time to reach the amplifier".
// Run each several times at a fixed -fuzztime and compare: the buckets build
// should reach the amplifier markedly sooner. Without the variable (the
// continuous rig and the CI fuzz shards, which run every declared target) the
// amplifier is only logged: reaching it is the expected A/B outcome, not a
// finding, and must not be reported as a crash.

const (
	amplifyThreshold = 32 // matches (see toyWork)
	toyMatchCap      = 64
	toyABEnv         = "KEYORIX_RESGUARD_TOY_AB"
)

var toyAllocSink []byte

// toyWork returns n = the number of positions where the byte equals its own
// index mod 256, and allocates 8 KiB·n so the alloc meter's base-2 bucket rises
// with n. Two properties make this the shape cost-guidance exists for:
//
//   - PARTIAL PROGRESS HAS NO NEW CODE EDGE. The match comparison's taken edge is
//     covered the first time ANY position matches; a second, third, … match adds
//     no edge. So the stock engine does not retain an input just because it has
//     more matches — without cost feedback, an input with 8 matches is discarded
//     exactly like one with 1, and progress cannot accumulate.
//   - IT IS NOT A CONSTANT COMPARISON the fuzzer can solve. The target `i%256` is
//     position-dependent, so go-fuzz's literal/comparison extraction does not
//     hand the answer over.
//
// FeedCoverage turns each higher allocation bucket (more matches) into a new
// edge, so the engine retains partial progress and climbs. The hypothesis: the
// buckets build reaches amplifyThreshold matches; the control does not, because
// it must land ~32 position-matches in a SINGLE input by luck.
func toyWork(data []byte) int {
	matches := 0
	for i, b := range data {
		if int(b) == i%256 {
			matches++
			if matches >= toyMatchCap {
				break
			}
		}
	}
	toyAllocSink = make([]byte, matches*8192)
	return matches
}

func fuzzToy(f *testing.F, useBuckets bool) {
	f.Add([]byte{0})                     // 1 match (index 0 holds 0) — a non-zero starting point
	f.Add([]byte{0, 1, 2, 3})            // 4 matches — seeds the gradient
	f.Add(make([]byte, 16))              // index 0 matches; a length to grow from
	p := New(f, Options{SampleEvery: 1}) // sample every input so alloc is always metered
	abRun := os.Getenv(toyABEnv) == "1"
	f.Fuzz(func(t *testing.T, data []byte) {
		var n int
		c := p.Measure(len(data), func() { n = toyWork(data) })
		if useBuckets {
			FeedCoverage(c)
		}
		if n >= amplifyThreshold {
			if !abRun {
				t.Logf("reached amplifier: n=%d (input %d bytes, alloc≈%d); set %s=1 to fail here", n, len(data), c.AllocBytes, toyABEnv)
				return
			}
			t.Fatalf("reached amplifier: n=%d (input %d bytes, alloc≈%d)", n, len(data), c.AllocBytes)
		}
	})
}

// FuzzToyAmplifyBuckets steers with cost buckets.
func FuzzToyAmplifyBuckets(f *testing.F) { fuzzToy(f, true) }

// FuzzToyAmplifyNoBuckets is the control: identical target, no cost feedback.
func FuzzToyAmplifyNoBuckets(f *testing.F) { fuzzToy(f, false) }
