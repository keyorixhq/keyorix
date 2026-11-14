package authzdiff

import (
	"math/rand"
	"os"
	"testing"

	"github.com/keyorixhq/keyorix/internal/fuzzutil"
)

// Swarm testing for the stateful authz sequence fuzzer (see SEQUENCE.md and the
// SW1 report). FuzzAuthzSeq takes a feature mask as its first fuzz argument and
// decodes each execution's step-kind alphabet through that mask
// (decodeSeqSwarm). This file holds:
//
//   - the seed-compatibility guard (all-ones mask == the original decoder),
//   - a distinct-sequence-shape census that measures, not assumes, that swarm
//     reaches alphabet subsets a uniform generator effectively never does,
//   - a planted harness-level defect reachable only when the step-kind alphabet
//     has grant and suspend available but revoke ABSENT, with an equal-budget
//     red proof that swarm finds it and uniform cannot,
//   - a fast standalone fuzz target (decode + plant only, no 3-world build) used
//     for the real-fuzzer arm of the red proof.
//
// None of this changes the shipped fuzzer's oracles or production code.

// TestDecodeSeqAllOnesMatchesUniform is the seed-compatibility guard: with an
// all-ones mask decodeSeqSwarm must be byte-identical to the original decoder
// (kind = b[0] % numSeqKinds, all other fields unchanged). This is what lets a
// pre-swarm seed keep its exact meaning once an all-ones mask is prepended.
// Red/green: flip the mask to anything that drops a kind and this fails.
func TestDecodeSeqAllOnesMatchesUniform(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	for range 4000 {
		n := r.Intn(seqMaxSteps*seqStepLen + 3)
		b := make([]byte, n)
		r.Read(b)
		got := decodeSeqSwarm(^uint64(0), b)
		// Reconstruct the original (pre-swarm) decoding inline.
		var want []seqStep
		for i := 0; i+seqStepLen <= len(b) && len(want) < seqMaxSteps; i += seqStepLen {
			s := b[i : i+seqStepLen]
			want = append(want, seqStep{
				Kind:    seqKind(int(s[0]) % int(numSeqKinds)),
				Actor:   seqActors[int(s[1])%len(seqActors)],
				Subject: seqSubjects[int(s[2])%len(seqSubjects)],
				T:       seqTargets[int(s[3])%len(seqTargets)],
				Role:    s[4] % 4,
				Bit:     s[4] / 4,
			})
		}
		if len(got) != len(want) {
			t.Fatalf("len mismatch: got %d want %d", len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("step %d: got %+v want %+v", i, got[i], want[i])
			}
		}
	}
}

// swarmPlantTriggered models a harness-level defect that is reachable only when
// the execution's enabled step-kind alphabet has grant AND suspend available but
// revoke ABSENT, and the realized sequence actually performs a grant and a
// suspend. A uniform generator always has revoke available (all-ones mask), so
// the guard `!sw.Has(skRevoke)` is false on every uniform execution and the
// defect is unreachable by uniform generation no matter how long it runs. Under
// swarm, masks that disable revoke occur in a constant fraction of executions,
// so the state is ordinary.
//
// This is the canonical swarm-testing shape: a feature (revoke) whose mere
// availability masks a bug between two other features (grant, suspend).
func swarmPlantTriggered(sw fuzzutil.Swarm, steps []seqStep) bool {
	if sw.Has(int(skRevoke)) {
		return false // revoke available -> the interaction is masked
	}
	var sawGrant, sawSuspend bool
	for _, st := range steps {
		switch st.Kind {
		case skGrant:
			sawGrant = true
		case skSuspend:
			sawSuspend = true
		}
	}
	return sawGrant && sawSuspend
}

// TestSwarmPlantUnreachableUnderUniform proves the first half of the red proof
// as a fast deterministic fact: over a large sample of inputs decoded with the
// all-ones (uniform) mask, the planted defect never triggers — because revoke is
// always in the alphabet. Equal-budget comparison against swarm is in
// TestSwarmPlantRedProof.
func TestSwarmPlantUnreachableUnderUniform(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	const budget = 2_000_000
	triggers := 0
	for range budget {
		b := make([]byte, seqMaxSteps*seqStepLen)
		r.Read(b)
		sw := fuzzutil.NewSwarm(^uint64(0), int(numSeqKinds))
		if swarmPlantTriggered(sw, decodeSeqSwarm(^uint64(0), b)) {
			triggers++
		}
	}
	if triggers != 0 {
		t.Fatalf("uniform generation triggered the plant %d/%d times; it must be structurally unreachable", triggers, budget)
	}
}

// TestSwarmPlantRedProof is the equal-budget red proof: same number of generated
// executions for each arm (identical per-execution cost, so equal execution
// count == equal wall-clock budget), repeated 3 times with different seeds.
// Uniform must find 0; swarm must find the defect. Numbers are logged for the
// report (honest even if swarm did not win — here it must, by construction).
func TestSwarmPlantRedProof(t *testing.T) {
	const budgetPerArm = 1_000_000
	for rep := range 3 {
		seed := int64(1000 + rep)
		uniform := runPlantArm(seed, budgetPerArm, true)
		swarm := runPlantArm(seed, budgetPerArm, false)
		t.Logf("red-proof rep=%d budget=%d: uniform detections=%d (first=%d) | swarm detections=%d (first=%d)",
			rep, budgetPerArm, uniform.detections, uniform.firstAt, swarm.detections, swarm.firstAt)
		if uniform.detections != 0 {
			t.Fatalf("rep=%d: uniform found the plant %d times, expected 0", rep, uniform.detections)
		}
		if swarm.detections == 0 {
			t.Fatalf("rep=%d: swarm did not find the plant in %d executions", rep, budgetPerArm)
		}
	}
}

type plantArmResult struct {
	detections int
	firstAt    int // 1-based execution index of the first detection, 0 if none
}

// runPlantArm runs one arm of the red proof. forceFull=true is the uniform arm
// (every execution uses the all-ones mask); false is the swarm arm (the mask is
// drawn from the input stream, exactly as the fuzzer supplies it).
func runPlantArm(seed int64, budget int, forceFull bool) plantArmResult {
	r := rand.New(rand.NewSource(seed))
	res := plantArmResult{}
	buf := make([]byte, 8+seqMaxSteps*seqStepLen)
	for i := 1; i <= budget; i++ {
		r.Read(buf)
		mask := ^uint64(0)
		if !forceFull {
			mask = beU64(buf[:8])
		}
		sw := fuzzutil.NewSwarm(mask, int(numSeqKinds))
		if swarmPlantTriggered(sw, decodeSeqSwarm(mask, buf[8:])) {
			res.detections++
			if res.firstAt == 0 {
				res.firstAt = i
			}
		}
	}
	return res
}

func beU64(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

// TestSwarmShapeCensus measures, over an equal budget, how many DISTINCT
// sequence shapes each generator reaches. Two notions of shape are counted:
//   - kind-presence: which step kinds appear at all (a bitmask over numSeqKinds);
//   - kind-sequence: the exact ordered tuple of step kinds.
//
// The swarm hypothesis is that uniform generation almost always makes every kind
// present (so its presence-mask is nearly always the full set), while swarm
// reaches many partial subsets — including subsets that omit a given kind, which
// is exactly what exercises masking/cancelling interactions. Logged for the
// report; asserted loosely so it is a measurement, not a brittle gate.
func TestSwarmShapeCensus(t *testing.T) {
	const budget = 300_000
	uniP, uniS := censusArm(2, budget, true)
	swP, swS := censusArm(2, budget, false)
	t.Logf("shape-census budget=%d: uniform presence-sets=%d kind-seqs=%d | swarm presence-sets=%d kind-seqs=%d",
		budget, uniP, uniS, swP, swS)
	if swP <= uniP {
		t.Fatalf("swarm reached %d distinct presence-sets, not more than uniform's %d", swP, uniP)
	}
}

func censusArm(seed int64, budget int, forceFull bool) (presenceSets, kindSeqs int) {
	r := rand.New(rand.NewSource(seed))
	presence := map[uint16]struct{}{}
	seqs := map[string]struct{}{}
	buf := make([]byte, 8+seqMaxSteps*seqStepLen)
	for range budget {
		r.Read(buf)
		mask := ^uint64(0)
		if !forceFull {
			mask = beU64(buf[:8])
		}
		steps := decodeSeqSwarm(mask, buf[8:])
		var pm uint16
		sq := make([]byte, 0, len(steps))
		for _, st := range steps {
			pm |= 1 << uint(st.Kind)
			sq = append(sq, byte(st.Kind))
		}
		presence[pm] = struct{}{}
		seqs[string(sq)] = struct{}{}
	}
	return len(presence), len(seqs)
}

// FuzzAuthzSeqSwarmPlant is the fast real-fuzzer arm of the red proof: it decodes
// the input exactly like FuzzAuthzSeq but runs ONLY the decoder and the planted
// oracle (no 3-world build), so it executes millions of inputs per second and a
// 540s run is a meaningful coverage-guided search. Normally it runs the swarm
// decoder; KEYORIX_SWARM_FORCE_FULL=1 forces the all-ones mask on every
// execution (the uniform arm). The swarm arm reports the plant in well under a
// second; the uniform arm cannot report it in any budget (revoke is always
// available). Inert as a unit test (the f.Fuzz body with seeds alone never
// triggers the plant).
func FuzzAuthzSeqSwarmPlant(f *testing.F) {
	forceFull := os.Getenv("KEYORIX_SWARM_FORCE_FULL") == "1"
	f.Add(^uint64(0), []byte{0, 0, 0, 0, 0, 2, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, mask uint64, data []byte) {
		if forceFull {
			mask = ^uint64(0)
		}
		sw := fuzzutil.NewSwarm(mask, int(numSeqKinds))
		if swarmPlantTriggered(sw, decodeSeqSwarm(mask, data)) {
			t.Errorf("SWARM-PLANT triggered: grant+suspend realized with revoke absent from the alphabet (mask=%#x)", mask)
		}
	})
}
