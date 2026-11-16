package resguard

import "math/bits"

// Cost-guided fuzzing (a PerfFuzz idea on the stock `go test -fuzz` engine).
//
// The native engine keeps and mutates an input only when it reaches a NEW code
// edge. Resource cost is not an edge, so a pathologically expensive input that
// touches no new code is discarded. FeedCoverage turns a cost VALUE into an
// edge: it maps each meter to the base-2 bucket of its magnitude and runs that
// bucket through a switch. The first time any meter reaches a higher bucket than
// ever seen, a new case executes — a new edge — and the engine retains the
// input and mutates it further, climbing the cost gradient toward the amplifier.
//
// Simplification, stated plainly: the switch is SHARED across meters (the edge
// is "some meter reached bucket B for the first time", not "the alloc meter
// specifically reached B"). That is enough to make the engine chase the single
// most-amplifying dimension, which is what the toy-target A/B test measures; a
// per-meter edge space is a LEFTOVER. If the A/B test shows no speed-up, that is
// reported, not hidden.
//
// Call FeedCoverage(cost) after Probe.Measure on every input, including
// unsampled ones (the cheap meters alone — wall, goroutines — already give a
// gradient).

// costSink is written by every bucket case so the compiler cannot prove the
// switch dead and fold it away; its value is never read.
var costSink uint8

// FeedCoverage runs every meter's magnitude through the bucket switch.
func FeedCoverage(c Cost) {
	feedBucket(uint64(c.Wall))
	feedBucket(uint64(c.CPU))
	feedBucket(c.AllocBytes)
	feedBucket(c.Mallocs)
	feedBucket(c.LiveHeap)
	feedBucket(uint64(nonNeg(c.Goroutines)))
	feedBucket(uint64(nonNeg(c.Threads)))
	feedBucket(uint64(nonNeg(c.OpenFDs)))
	feedBucket(c.WriteBytes)
	feedBucket(uint64(nonNeg64(c.DiskBytes)))
	feedBucket(uint64(nonNeg64(c.DiskBlocks)))
	feedBucket(uint64(nonNeg(c.DiskFiles)))
	feedBucket(uint64(c.Dials))
	feedBucket(uint64(c.NonLoopbackDials))
	feedBucket(uint64(nonNeg64(c.NetBytesOut)))
	feedBucket(uint64(c.Sleep))
	feedBucket(uint64(nonNeg64(c.LogBytes)))
	feedBucket(uint64(c.DBQueries))
	feedBucket(uint64(nonNeg64(c.DBRows)))
}

// feedBucket runs the base-2 magnitude of v through a switch with one case per
// bucket (0..64). bits.Len64 is the index of the highest set bit, i.e. the
// base-2 bucket. The switch, not the arithmetic, is what the coverage
// instrumentation sees.
//
//go:noinline
func feedBucket(v uint64) {
	switch bits.Len64(v) {
	case 0:
		costSink++
	case 1:
		costSink += 2
	case 2:
		costSink += 3
	case 3:
		costSink += 5
	case 4:
		costSink += 7
	case 5:
		costSink += 11
	case 6:
		costSink += 13
	case 7:
		costSink += 17
	case 8:
		costSink += 19
	case 9:
		costSink += 23
	case 10:
		costSink += 29
	case 11:
		costSink += 31
	case 12:
		costSink += 37
	case 13:
		costSink += 41
	case 14:
		costSink += 43
	case 15:
		costSink += 47
	case 16:
		costSink += 53
	case 17:
		costSink += 59
	case 18:
		costSink += 61
	case 19:
		costSink += 67
	case 20:
		costSink += 71
	case 21:
		costSink += 73
	case 22:
		costSink += 79
	case 23:
		costSink += 83
	case 24:
		costSink += 89
	case 25:
		costSink += 97
	case 26:
		costSink += 101
	case 27:
		costSink += 103
	case 28:
		costSink += 107
	case 29:
		costSink += 109
	case 30:
		costSink += 113
	case 31:
		costSink += 127
	case 32:
		costSink += 131
	default:
		// buckets 33..64: one shared tail edge (values this large are already
		// far past any legitimate per-input cost; reaching here at all is the
		// signal).
		costSink += 139
	}
}

func nonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func nonNeg64(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}

// Bucket is the exported base-2 bucket of v, for tests and reporting.
func Bucket(v uint64) int { return bits.Len64(v) }
