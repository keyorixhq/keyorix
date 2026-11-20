package http

import (
	"testing"
)

// recordingTB captures Errorf so the verdict of checkGrowthMinRise can be asserted.
type recordingTB struct {
	testing.TB
	errs int
}

func (r *recordingTB) Helper()               {}
func (r *recordingTB) Logf(string, ...any)   {}
func (r *recordingTB) Errorf(string, ...any) { r.errs++ }

func heapSamples(opsStep int, heap ...uint64) []soakSample {
	out := make([]soakSample, len(heap))
	for i, h := range heap {
		out[i] = soakSample{ops: i * opsStep, heapInuse: h}
	}
	return out
}

func heapOf(s soakSample) float64 { return float64(s.heapInuse) }

// #4389: the heap rows of the two merge-queue failures after the 2026-11-17 fix
// (CI runs 44219784208 postgres, 44233643310 sqlite; 1500 ops, sample every 150).
// Under 1 MiB of rise extrapolated to 7-9 MiB/10k must not be called a leak.
func TestSoakHeapOracle_NoiseOfTheRealFailuresIsNotALeak(t *testing.T) {
	cases := map[string][]uint64{
		"postgres": {146300928, 146644992, 144695296, 144515072, 144490496, 144564224, 144654336, 144670720, 144769024, 144941056, 145350656},
		"sqlite":   {76824576, 78815232, 76881920, 75186176, 73515008, 70377472, 70139904, 70451200, 70557696, 70688768, 70787072},
	}
	for name, heap := range cases {
		t.Run(name, func(t *testing.T) {
			rec := &recordingTB{TB: t}
			checkGrowthMinRise(rec, "heap-inuse/"+name, heapSamples(150, heap...), soakMaxHeapSlopePer10kBytes, soakHeapMinRiseBytes, heapOf)
			if rec.errs != 0 {
				t.Fatalf("noise-sized heap rise reported as a leak")
			}
			// Without the floor the same samples are a violation: the test is not vacuous.
			rec = &recordingTB{TB: t}
			checkGrowth(rec, "heap-inuse/"+name, heapSamples(150, heap...), soakMaxHeapSlopePer10kBytes, heapOf)
			if rec.errs == 0 {
				t.Fatalf("expected the floorless check to flag the real failing samples")
			}
		})
	}
}

// A real per-op leak (10 KiB/op) still fails the default 1500-op run.
func TestSoakHeapOracle_PlantedLeakStillFails(t *testing.T) {
	heap := make([]uint64, 11)
	for i := range heap {
		heap[i] = 100<<20 + uint64(i)*150*10<<10
	}
	rec := &recordingTB{TB: t}
	checkGrowthMinRise(rec, "heap-inuse/planted", heapSamples(150, heap...), soakMaxHeapSlopePer10kBytes, soakHeapMinRiseBytes, heapOf)
	if rec.errs != 1 {
		t.Fatalf("planted 10 KiB/op leak: want 1 violation, got %d", rec.errs)
	}
}
