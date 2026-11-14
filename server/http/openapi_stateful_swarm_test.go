package http

import (
	"math/rand"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// Swarm testing for FuzzOpenAPIStateful (see the SW1 report). The fuzzer takes a
// swarm feature mask as its first fuzz argument and selects each step's
// operation through that mask (osRunIteration: sw.Pick(rd.u16())), so an
// execution whose mask disables an operation never issues it.
//
// Unlike the authz-sequence fuzzer (8 step kinds), the OpenAPI alphabet has many
// operations but each execution only issues up to 12. A uniform generator
// therefore spreads those 12 steps thinly across the whole alphabet and rarely
// exercises any specific operation twice, let alone a chosen interaction; swarm,
// by restricting an execution to a small enabled subset (the density-exponent
// scheme in internal/fuzzutil.Swarm), exercises the operations in that subset
// repeatedly and together, and — crucially — makes a chosen operation ABSENT in
// a constant fraction of executions. The census and the planted defect below
// measure that, with no HTTP calls (operation SELECTION is the thing swarm
// changes; request-argument byte consumption is abstracted away deliberately, as
// it does not affect which operations are available or chosen).

// osSimSelect mirrors the operation-selection step of osRunIteration exactly
// (sw.Pick over a u16 selector), abstracting the per-step request generation.
// It returns the enabled-subset-filtered operation indices an execution issues.
func osSimSelect(sw fuzzutil.Swarm, r *rand.Rand) []int {
	numSteps := 1 + r.Intn(12)
	ops := make([]int, numSteps)
	for i := range ops {
		ops[i] = sw.Pick(int(uint16(r.Uint32())))
	}
	return ops
}

// TestOSFSwarmAllOnesIsUniform is the seed-compatibility guard for this
// alphabet: with an all-ones mask, Pick over len(osOps) is exactly the original
// selection (selector % len(osOps)), so a pre-swarm seed keeps its meaning once
// an all-ones mask is prepended.
func TestOSFSwarmAllOnesIsUniform(t *testing.T) {
	osLoadSpec(t)
	if len(osOps) == 0 {
		t.Skip("no operations enumerated")
	}
	sw := fuzzutil.NewSwarm(^uint64(0), len(osOps))
	if sw.Len() != len(osOps) {
		t.Fatalf("all-ones enabled %d ops, want %d", sw.Len(), len(osOps))
	}
	for sel := 0; sel < 70000; sel++ {
		if got, want := sw.Pick(sel), sel%len(osOps); got != want {
			t.Fatalf("all-ones Pick(%d)=%d, want %d (len=%d)", sel, got, want, len(osOps))
		}
	}
}

// osPlantTriad picks three distinct low operation indices. The planted defect
// depends on two of them being BOTH exercised while the third is ABSENT from the
// alphabet — a shape a uniform generator cannot reach (it always has every
// operation available), making this an at-all swarm win.
func osPlantTriad() (a, b, c int) { return 0, 1, 2 }

func contains(ops []int, x int) bool {
	for _, o := range ops {
		if o == x {
			return true
		}
	}
	return false
}

// osPlantTriggered models the harness-level defect: operations a and b are both
// exercised in this execution AND operation c is absent from the alphabet
// (sw disables it). Under a uniform (all-ones) generator c is always available,
// so the defect is unreachable no matter how long it runs.
func osPlantTriggered(sw fuzzutil.Swarm, ops []int, a, b, c int) bool {
	if sw.Has(c) {
		return false // c available -> the interaction is masked
	}
	return contains(ops, a) && contains(ops, b)
}

// TestOSFSwarmPlantRedProof is the equal-budget red proof: same number of
// generated executions per arm (identical per-execution cost ⇒ equal execution
// count == equal wall-clock budget), repeated 3 times. Uniform must find 0 (it
// always has operation c available); swarm finds the defect. Numbers are logged
// for the report, honestly.
func TestOSFSwarmPlantRedProof(t *testing.T) {
	osLoadSpec(t)
	if len(osOps) < 3 {
		t.Skip("need at least 3 operations")
	}
	a, b, c := osPlantTriad()
	const budget = 500_000
	for rep := range 3 {
		seed := int64(2000 + rep)
		uni := osPlantArm(seed, budget, a, b, c, true)
		sw := osPlantArm(seed, budget, a, b, c, false)
		t.Logf("osf plant rep=%d budget=%d ops=(a=%d,b=%d,c=%d of %d): uniform detections=%d (first=%d) | swarm detections=%d (first=%d)",
			rep, budget, a, b, c, len(osOps), uni.detections, uni.firstAt, sw.detections, sw.firstAt)
		if uni.detections != 0 {
			t.Fatalf("rep=%d: uniform found the plant %d times, expected 0 (c is always available)", rep, uni.detections)
		}
		if sw.detections == 0 {
			t.Fatalf("rep=%d: swarm did not find the plant in %d executions", rep, budget)
		}
	}
}

type osArmResult struct {
	detections int
	firstAt    int
}

func osPlantArm(seed int64, budget, a, b, c int, forceFull bool) osArmResult {
	r := rand.New(rand.NewSource(seed))
	res := osArmResult{}
	for i := 1; i <= budget; i++ {
		mask := ^uint64(0)
		if !forceFull {
			mask = r.Uint64()
		}
		sw := fuzzutil.NewSwarm(mask, len(osOps))
		if osPlantTriggered(sw, osSimSelect(sw, r), a, b, c) {
			res.detections++
			if res.firstAt == 0 {
				res.firstAt = i
			}
		}
	}
	return res
}

// TestOSFSwarmShapeCensus measures, over an equal budget, the single-execution
// maximum repeat-count of one operation (depth) and the number of distinct
// unordered operation PAIRS co-occurring within an execution. Swarm concentrates
// the step budget on a small enabled subset, so it exercises each enabled
// operation more often per execution (greater depth) — reaching deeper
// per-operation state than a uniform generator that spreads 12 steps thinly over
// the whole alphabet. Logged for the report.
func TestOSFSwarmShapeCensus(t *testing.T) {
	osLoadSpec(t)
	if len(osOps) < 2 {
		t.Skip("need at least 2 operations")
	}
	const budget = 200_000
	uniPairs, uniDepth := osCensusArm(3, budget, true)
	swPairs, swDepth := osCensusArm(3, budget, false)
	t.Logf("osf shape-census budget=%d ops=%d: uniform distinct-pairs=%d max-depth=%d | swarm distinct-pairs=%d max-depth=%d",
		budget, len(osOps), uniPairs, uniDepth, swPairs, swDepth)
	if swDepth <= uniDepth {
		t.Fatalf("swarm max per-execution operation depth (%d) did not exceed uniform's (%d)", swDepth, uniDepth)
	}
}

func osCensusArm(seed int64, budget int, forceFull bool) (distinctPairs, maxDepth int) {
	r := rand.New(rand.NewSource(seed))
	pairs := map[[2]int]struct{}{}
	for range budget {
		mask := ^uint64(0)
		if !forceFull {
			mask = r.Uint64()
		}
		sw := fuzzutil.NewSwarm(mask, len(osOps))
		ops := osSimSelect(sw, r)
		counts := map[int]int{}
		for _, o := range ops {
			counts[o]++
			if counts[o] > maxDepth {
				maxDepth = counts[o]
			}
		}
		uniq := make([]int, 0, len(counts))
		for o := range counts {
			uniq = append(uniq, o)
		}
		for i := range uniq {
			for j := i + 1; j < len(uniq); j++ {
				lo, hi := uniq[i], uniq[j]
				if lo > hi {
					lo, hi = hi, lo
				}
				pairs[[2]int{lo, hi}] = struct{}{}
			}
		}
	}
	return len(pairs), maxDepth
}
