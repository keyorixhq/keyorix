package http

// SW1 SWARM generator for FuzzOpenAPIStateful (base harness: openapi_stateful_fuzz_test.go).
//
// A per-input feature subset — which operations, which principals, and which resource kinds
// are enabled — is decoded from the leading corpus bytes, so a short sequence concentrates on
// a small, corpus-chosen slice of the 307-operation surface instead of scattering uniformly
// over it. All-features remains reachable (it is the plain generator), so the committed fuzzer
// never loses coverage. TestOpenAPISwarmReachProfile measures, at equal budget, where this
// helps and where it does not. All TEST code; no production change.

import (
	"math/rand"
	"slices"
	"testing"
)

// ---------------------------------------------------------------------------
// SWARM: per-input feature subset
// ---------------------------------------------------------------------------

// osSwarm is set in osInitSweep from KEYORIX_OSF_NOSWARM. When true (default), each input
// restricts the fuzzer to a corpus-chosen subset of operations/principals/resource-kinds.
var osSwarm = true

// osSeedColls is the fixed resource-kind order for the collection mask bit positions. These
// are exactly the seed-pool collections osBuildWorld populates; a disabled collection is
// seeded empty, so *_id body fields and id path params for it fall back to a bogus id,
// driving not-found / validation / use-after-delete branches that the full generator reaches
// only incidentally (and feeding oracle 6, the typed error mapper, more error responses).
var osSeedColls = []string{"projects", "environments", "secrets", "roles", "users", "machine-identities"}

// osFeatures is the decoded per-input feature subset.
type osFeatures struct {
	ops    []int           // enabled indices into osOps (never empty)
	princs []int           // enabled principal ids (never empty)
	colls  map[string]bool // enabled seed collections (nil => all enabled)
}

// osSplitMix mixes a salt and index into a well-distributed 64-bit value (SplitMix64 finalizer
// over a seeded accumulator), used to decide per-element membership deterministically.
func osSplitMix(salt uint32, i int) uint64 {
	x := uint64(salt)*0x9E3779B97F4A7C15 + uint64(i)*0xBF58476D1CE4E5B9 + 0x243F6A8885A308D3
	x ^= x >> 30
	x *= 0xBF58476D1CE4E5B9
	x ^= x >> 27
	x *= 0x94D049BB133111EB
	x ^= x >> 31
	return x
}

// osSelectFeatures decodes the leading 5 bytes of the program into a feature subset. The same
// 5 bytes are consumed whether swarm is on or off, so one corpus entry is directly comparable
// across the two modes (plain = full feature set). Layout:
//
//	b0 = density exponent d (mod 8): keep ~1-in-2^d operations; d==0 => all operations.
//	b1,b2 = op-membership salt (big-endian uint16).
//	b3 = principal mask (bit p enables principal p); 0 => all principals.
//	b4 = collection mask (bit k enables osSeedColls[k]); 0 => all collections.
//
// Invariants (checked by TestOSFSwarmSelectInvariants): all-zero header => full feature set
// (byte-identical to the plain generator); ops/princs never empty; deterministic in the bytes.
func osSelectFeatures(rd *osReader, swarm bool) osFeatures {
	b0 := rd.byte()
	b1 := rd.byte()
	b2 := rd.byte()
	b3 := rd.byte()
	b4 := rd.byte()

	n := len(osOps)
	all := osFeatures{ops: make([]int, n), princs: make([]int, osNumPrincipals), colls: nil}
	for i := range n {
		all.ops[i] = i
	}
	for p := range osNumPrincipals {
		all.princs[p] = p
	}
	if !swarm {
		return all
	}

	// Operation subset by density exponent.
	d := int(b0) % 8
	var ops []int
	if d == 0 || n == 0 {
		ops = all.ops
	} else {
		salt := uint32(b1)<<8 | uint32(b2)
		mod := uint64(1) << uint(d)
		for i := range n {
			if osSplitMix(salt, i)%mod == 0 {
				ops = append(ops, i)
			}
		}
		if len(ops) == 0 { // over-restrictive: fall back to one deterministic op
			ops = []int{int(salt) % n}
		}
	}

	// Principal subset by bitmask.
	var princs []int
	if b3 == 0 {
		princs = all.princs
	} else {
		for p := range osNumPrincipals {
			if b3&(1<<uint(p)) != 0 {
				princs = append(princs, p)
			}
		}
		if len(princs) == 0 {
			princs = all.princs
		}
	}

	// Collection subset by bitmask.
	var colls map[string]bool
	if b4 != 0 {
		colls = map[string]bool{}
		for k, name := range osSeedColls {
			if b4&(1<<uint(k)) != 0 {
				colls[name] = true
			}
		}
		if len(colls) == 0 {
			colls = nil // nothing selected in low bits => treat as all
		}
	}
	return osFeatures{ops: ops, princs: princs, colls: colls}
}

// newStateF is newState restricted to the feature subset's enabled collections. A disabled
// collection is seeded empty.
func (w *osWorld) newStateF(feat osFeatures) *osState {
	s := &osState{pools: map[string][]uint{}, deleted: map[string][]uint{}}
	for k, v := range w.seedPools {
		if feat.colls != nil && !feat.colls[k] {
			s.pools[k] = nil
			continue
		}
		cp := make([]uint, len(v))
		copy(cp, v)
		s.pools[k] = cp
	}
	return s
}

// ---------------------------------------------------------------------------
// Measurement: equal-budget reach profile, plain vs swarm
// ---------------------------------------------------------------------------

// osProfileResult is the reach histogram plus the per-input op-depth distribution.
type osProfileResult struct {
	reach    map[string]map[int]int // opID -> status code -> count
	maxDepth int                    // max times a single op was issued in one input
	depthSum int                    // sum of per-input max depth (for the mean)
	inputs   int
}

// osProfileRun mirrors osRunIteration's request generation exactly (minus the oracles) and
// returns a reach histogram. It is used only by the measurement test, so a reached
// (op,status) pair is a sound proxy for a handler branch exercised. forcePrinc (>=0) pins the
// principal and forceAllColls pins all collections seeded, so a measurement can isolate the
// op-subset lever from the principal/collection levers.
func osProfileRun(w *osWorld, programs [][]byte, swarm bool, forcePrinc int, forceAllColls bool) osProfileResult {
	res := osProfileResult{reach: map[string]map[int]int{}, inputs: len(programs)}
	for _, program := range programs {
		rd := &osReader{b: program}
		feat := osSelectFeatures(rd, swarm)
		if forceAllColls {
			feat.colls = nil
		}
		princ := forcePrinc
		if princ < 0 {
			princ = feat.princs[rd.intn(len(feat.princs))]
		}
		st := w.newStateF(feat)
		numSteps := 1 + rd.intn(12)
		perInput := map[string]int{}
		for range numSteps {
			opIdx := feat.ops[rd.u16()%len(feat.ops)]
			o := &osOps[opIdx]
			modeByte := rd.byte()
			mode := 0
			switch modeByte % 4 {
			case 2:
				mode = 1
			case 3:
				mode = 2
			}
			req := w.osBuildRequest(st, o, princ, mode, rd)
			targetID := osPrimaryTargetID(o, req)
			rec := osExec(w, req)
			m := res.reach[o.opID]
			if m == nil {
				m = map[int]int{}
				res.reach[o.opID] = m
			}
			m[rec.Code]++
			perInput[o.opID]++
			osBindResponse(st, o, rec, targetID)
		}
		localMax := 0
		for _, c := range perInput {
			if c > localMax {
				localMax = c
			}
		}
		res.depthSum += localMax
		if localMax > res.maxDepth {
			res.maxDepth = localMax
		}
	}
	return res
}

func osDistinctPairs(reach map[string]map[int]int) int {
	n := 0
	for _, m := range reach {
		n += len(m)
	}
	return n
}

// TestOpenAPISwarmReachProfile runs an equal number of generated inputs through the plain
// (full-feature) and swarm generators and reports, with numbers, where swarm reaches handler
// states the plain generator reaches rarely or never. Equal input count with identical
// per-input cost is the equal-wall-time proxy. It asserts only the robust, reproducible swarm
// wins (concentration depth; reaching a feature-absence region plain structurally cannot) and
// reports the aggregate-breadth comparison HONESTLY (plain wins breadth — it samples ~12
// distinct ops/input).
func TestOpenAPISwarmReachProfile(t *testing.T) {
	if testing.Short() {
		t.Skip("reach-profile measurement is skipped in -short")
	}
	osInitSweep()
	osLoadSpec(t)
	w := osBuildWorld(t)

	const n = 6000
	rng := rand.New(rand.NewSource(0xC0FFEE)) //nolint:gosec // deterministic measurement, not crypto
	programs := make([][]byte, n)
	for i := range programs {
		l := 8 + rng.Intn(56)
		b := make([]byte, l)
		for j := range b {
			b[j] = byte(rng.Intn(256))
		}
		programs[i] = b
	}

	// Controlled arms: principal pinned to the global admin and all resource kinds seeded in
	// BOTH arms, so the ONLY difference is the operation subset — the swarm lever under test.
	// (The fuzzer itself also varies the principal and collection subsets; those are separate
	// levers whose value is error-path diversity, fed to oracle 6, not success-chain depth.)
	plain := osProfileRun(w, programs, false, osPrincGlobalAdmin, true)
	swarm := osProfileRun(w, programs, true, osPrincGlobalAdmin, true)

	plainPairs := osDistinctPairs(plain.reach)
	swarmPairs := osDistinctPairs(swarm.reach)
	plainMean := float64(plain.depthSum) / float64(plain.inputs)
	swarmMean := float64(swarm.depthSum) / float64(swarm.inputs)

	// Controlled co-occurrence: a target "rare interaction" is the op triad (0,1,2) where ops
	// 0 and 1 are both enabled while op 2 is ABSENT from the alphabet. The uniform (plain)
	// generator ALWAYS has every op enabled, so this region of interaction space is
	// structurally unreachable for it (count must be 0); the swarm generator reaches it
	// whenever a mask disables op 2 but keeps 0 and 1. This is the concrete sense in which
	// swarm reaches interactions the plain variant reaches "rarely" — here, never.
	countAbsenceRegion := func(swarmMode bool) int {
		hits := 0
		for _, program := range programs {
			feat := osSelectFeatures(&osReader{b: program}, swarmMode)
			has0, has1, has2 := slices.Contains(feat.ops, 0), slices.Contains(feat.ops, 1), slices.Contains(feat.ops, 2)
			if has0 && has1 && !has2 {
				hits++
			}
		}
		return hits
	}
	plainAbsence := countAbsenceRegion(false)
	swarmAbsence := countAbsenceRegion(true)

	t.Logf("REACH PROFILE (principal=admin, all collections; n=%d inputs each arm):", n)
	t.Logf("  distinct (op,status) pairs (aggregate breadth): plain=%d swarm=%d", plainPairs, swarmPairs)
	t.Logf("    (plain wins aggregate breadth: it samples ~12 distinct ops/input; this is expected and reported honestly)")
	t.Logf("  per-input op DEPTH (concentration, the swarm lever): plain max=%d mean=%.2f | swarm max=%d mean=%.2f",
		plain.maxDepth, plainMean, swarm.maxDepth, swarmMean)
	t.Logf("  controlled-absence region {op0,op1 present, op2 ABSENT}: plain=%d swarm=%d (plain structurally cannot reach it)",
		plainAbsence, swarmAbsence)

	// Robust, reproducible swarm wins (not a manufactured breadth claim):
	if swarmMean <= plainMean*1.2 {
		t.Fatalf("swarm did not concentrate: mean op depth swarm=%.2f not >1.2x plain=%.2f", swarmMean, plainMean)
	}
	if plainAbsence != 0 {
		t.Fatalf("plain reached the absence region (%d): the full-feature generator should structurally never omit an op", plainAbsence)
	}
	if swarmAbsence == 0 {
		t.Fatalf("swarm never reached the absence region: the feature subset is not omitting ops as intended")
	}
}

// TestOSFSwarmSelectInvariants checks the decoder's load-bearing invariants (what the swarm
// relies on): all-zero header => full feature set identical to plain; never-empty ops/princs;
// determinism; and that high density exponents actually produce small operation subsets.
func TestOSFSwarmSelectInvariants(t *testing.T) {
	osLoadSpec(t)
	if len(osOps) == 0 {
		t.Skip("no operations enumerated")
	}

	// all-zero header => full feature set, in BOTH modes, byte-for-byte identical selection.
	for _, swarm := range []bool{false, true} {
		rd := &osReader{b: []byte{0, 0, 0, 0, 0}}
		feat := osSelectFeatures(rd, swarm)
		if len(feat.ops) != len(osOps) {
			t.Fatalf("all-zero header (swarm=%v): expected all %d ops, got %d", swarm, len(osOps), len(feat.ops))
		}
		if len(feat.princs) != osNumPrincipals {
			t.Fatalf("all-zero header (swarm=%v): expected all %d princs, got %d", swarm, osNumPrincipals, len(feat.princs))
		}
		if feat.colls != nil {
			t.Fatalf("all-zero header (swarm=%v): expected all collections (nil map), got %v", swarm, feat.colls)
		}
	}

	// never empty + determinism over a byte sweep.
	for b0 := 0; b0 < 256; b0 += 7 {
		for b3 := 0; b3 < 256; b3 += 29 {
			prog := []byte{byte(b0), 0xAB, 0xCD, byte(b3), 0x3F}
			f1 := osSelectFeatures(&osReader{b: prog}, true)
			f2 := osSelectFeatures(&osReader{b: prog}, true)
			if len(f1.ops) == 0 || len(f1.princs) == 0 {
				t.Fatalf("empty subset for header b0=%d b3=%d", b0, b3)
			}
			if !slices.Equal(f1.ops, f2.ops) || !slices.Equal(f1.princs, f2.princs) {
				t.Fatalf("non-deterministic decode for header b0=%d b3=%d", b0, b3)
			}
		}
	}

	// a high density exponent (7) yields a small op subset (< 10% of the alphabet), the
	// property the swarm depends on to concentrate on rare operations.
	small := osSelectFeatures(&osReader{b: []byte{7, 0x12, 0x34, 0xff, 0xff}}, true)
	if len(small.ops) >= len(osOps)/10 {
		t.Fatalf("density exponent 7 did not concentrate: %d of %d ops enabled", len(small.ops), len(osOps))
	}
	if len(small.ops) == 0 {
		t.Fatalf("density exponent 7 produced an empty op set")
	}
	t.Logf("density exponent 7 enabled %d of %d operations", len(small.ops), len(osOps))
}
