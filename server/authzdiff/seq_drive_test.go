package authzdiff

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// hand-written benign sequences: each state change is undone or irrelevant to
// the probes, and every probe stays equal to the model.
var seqControls = [][]seqStep{
	nil,
	{{skGrant, pkGlobalAdmin, pkNone, tA, 0, 0}, {skRevoke, pkGlobalAdmin, pkNone, tA, 0, 0}},
	{{skSuspend, pkGlobalAdmin, pkViewer, tA, 0, 0}, {skReactivate, pkGlobalAdmin, pkViewer, tA, 0, 0}},
	{{skGroupAdd, pkGlobalAdmin, pkNone, tGlobal, 0, 0}, {skGroupRemove, pkGlobalAdmin, pkNone, tGlobal, 0, 0}},
	{{skPermToggle, pkGlobalAdmin, pkCustom, tA, 0, 0}, {skPermToggle, pkGlobalAdmin, pkCustom, tA, 0, 0}},
	{{skGrant, pkViewer, pkNone, tA, 0, 0}, {skRevoke, pkNone, pkViewer, tA, 0, 0}},
}

// TestSeqControl: the zero-step baseline and the first benign sequence run in the
// default `go test`; AUTHZSEQ_SELFTEST=1 runs all of them (about 12 s).
func TestSeqControl(t *testing.T) {
	list := seqControls[:2]
	if os.Getenv("AUTHZSEQ_SELFTEST") == "1" {
		list = seqControls
	}
	for i, steps := range list {
		fs := runSeq(t, steps, nil, nil)
		for _, f := range fs {
			t.Errorf("control %d: step %d: %s", i, f.Step, f.Class)
		}
	}
}

// plants: harness-level defects, each with the sequence that must expose it and
// the oracle class that must fire.
type seqPlant struct {
	fault seqFault
	steps []seqStep
	class string
}

func seqPlants() []seqPlant {
	return []seqPlant{
		{
			fault: seqFault{name: "revoke-noop", skipDo: func(l layer, st seqStep) bool { return l == layerREST && st.Kind == skRevoke }},
			steps: []seqStep{{skGrant, pkGlobalAdmin, pkNone, tA, 0, 0}, {skRevoke, pkGlobalAdmin, pkNone, tA, 0, 0}},
			class: "O-E:revoked-row-still-present",
		},
		{
			fault: seqFault{name: "stale-allow", probe: func(l layer, p *principal, t tgt, lg *leg, o *legOutcome) *legOutcome {
				if l == layerGRPC && p.kind == pkViewer && t == tA && o.Outcome == Denied {
					return &legOutcome{Outcome: Allowed, Detail: "planted-stale"}
				}
				return o
			}},
			steps: []seqStep{{skRevoke, pkGlobalAdmin, pkViewer, tA, 0, 0}},
			class: "O-P:allowed-but-model-denies",
		},
		{
			fault: seqFault{name: "suspend-ignored", probe: func(l layer, p *principal, t tgt, lg *leg, o *legOutcome) *legOutcome {
				if l == layerREST && p.kind == pkViewer && o.Outcome == Denied {
					return &legOutcome{Outcome: Allowed, Detail: "planted-suspend-ignored"}
				}
				return o
			}},
			steps: []seqStep{{skSuspend, pkGlobalAdmin, pkViewer, tA, 0, 0}},
			class: "O-P:layers-disagree",
		},
	}
}

// TestSeqPlantsAreDetected: opt-in (AUTHZSEQ_SELFTEST=1), about 8 s.
func TestSeqPlantsAreDetected(t *testing.T) {
	if os.Getenv("AUTHZSEQ_SELFTEST") != "1" {
		t.Skip("set AUTHZSEQ_SELFTEST=1")
	}
	for _, pl := range seqPlants() {
		t.Run(pl.fault.name, func(t *testing.T) {
			if clean := runSeq(t, pl.steps, nil, nil); len(clean) != 0 {
				t.Fatalf("sequence is not clean without the plant: %v", clean)
			}
			fs := runSeq(t, pl.steps, &pl.fault, nil)
			for _, f := range fs {
				if classKind(f.Class) == pl.class {
					return
				}
			}
			t.Fatalf("plant %s not detected as %s; findings=%v", pl.fault.name, pl.class, fs)
		})
	}
}

func genSeq(r *rand.Rand) []seqStep {
	n := 1 + r.Intn(seqMaxSteps)
	b := make([]byte, n*seqStepLen)
	r.Read(b)
	return decodeSeq(b)
}

// privateSink writes a candidate's minimal sequence to $AUTHZSEQ_PRIVATE (a
// file outside the repository). Nothing but counts and class kinds is logged.
func privateSink(class string, steps []seqStep, detail string) {
	path := os.Getenv("AUTHZSEQ_PRIVATE")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = fmt.Fprintf(f, "## %s %s\n%s\n%s\n\n", time.Now().UTC().Format(time.RFC3339), class, detail, describe(steps))
}

// TestSeqSweep: AUTHZSEQ_SWEEP=1 [AUTHZSEQ_N=600] [AUTHZSEQ_SEED=1] [AUTHZSEQ_CAP=30m].
func TestSeqSweep(t *testing.T) {
	if os.Getenv("AUTHZSEQ_SWEEP") != "1" {
		t.Skip("set AUTHZSEQ_SWEEP=1")
	}
	n, _ := strconv.Atoi(os.Getenv("AUTHZSEQ_N"))
	if n == 0 {
		n = 600
	}
	seed, _ := strconv.Atoi(os.Getenv("AUTHZSEQ_SEED"))
	if seed == 0 {
		seed = 1
	}
	capD := 30 * time.Minute
	if v := os.Getenv("AUTHZSEQ_CAP"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			capD = d
		}
	}
	stats := newSeqStats()
	start := time.Now()
	byClass := map[string]int{}
	singleStep := 0
	ran := 0
	first, _ := strconv.Atoi(os.Getenv("AUTHZSEQ_START"))
	for i := first; i < first+n && time.Since(start) < capD; i++ {
		steps := genSeq(rand.New(rand.NewSource(int64(seed*1_000_000 + i))))
		fs := runSeq(t, steps, nil, stats)
		ran++
		if len(fs) == 0 {
			continue
		}
		// Cheap first: if the failing step alone reproduces the class, it is
		// single-step behaviour and needs no shrinking.
		if fs[0].Step >= 0 && fs[0].Step < len(steps) {
			if alone := runSeq(t, steps[fs[0].Step:fs[0].Step+1], nil, nil); len(alone) > 0 && classKind(alone[0].Class) == classKind(fs[0].Class) {
				singleStep++
				byClass["single-step:"+classKind(fs[0].Class)]++
				continue
			}
		}
		min := shrink(t, steps, nil, 40)
		fs = runSeq(t, min, nil, nil)
		if len(fs) == 0 {
			continue
		}
		kind := classKind(fs[0].Class)
		// single-step replay: the failing step alone from a fresh world
		if len(min) > 1 && fs[0].Step >= 0 && fs[0].Step < len(min) {
			if alone := runSeq(t, min[fs[0].Step:fs[0].Step+1], nil, nil); len(alone) > 0 && classKind(alone[0].Class) == kind {
				singleStep++
				byClass["single-step:"+kind]++
				continue
			}
		}
		if len(min) == 1 {
			singleStep++
			byClass["single-step:"+kind]++
			continue
		}
		byClass["CANDIDATE:"+kind]++
		privateSink(kind, min, fs[0].Class)
	}
	keys := make([]string, 0, len(byClass))
	for k := range byClass {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var cov []string
	for k := range numSeqKinds {
		cov = append(cov, fmt.Sprintf("%s=%d/%d", seqKindNames[k], stats.kindAllowed[k], stats.kindDenied[k]))
	}
	t.Logf("SEQ-SWEEP sequences=%d steps=%d probes=%d elapsed=%s single-step=%d", ran, stats.steps, stats.probes, time.Since(start).Round(time.Second), singleStep)
	t.Logf("SEQ-SWEEP coverage allowed/denied: %s", strings.Join(cov, " "))
	for _, k := range keys {
		t.Logf("SEQ-SWEEP class %s x%d", k, byClass[k])
	}
}

func FuzzAuthzSeq(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add([]byte{2, 0, 1, 0, 0, 3, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		steps := decodeSeq(data)
		fs := runSeq(t, steps, nil, nil)
		if len(fs) == 0 {
			return
		}
		min := shrink(t, steps, nil, 30)
		fs = runSeq(t, min, nil, nil)
		if len(fs) == 0 {
			return
		}
		kind := classKind(fs[0].Class)
		if len(min) == 1 {
			t.Logf("single-step %s", kind)
			return
		}
		if len(min) > 1 && fs[0].Step >= 0 && fs[0].Step < len(min) {
			if alone := runSeq(t, min[fs[0].Step:fs[0].Step+1], nil, nil); len(alone) > 0 && classKind(alone[0].Class) == kind {
				t.Logf("single-step %s", kind)
				return
			}
		}
		privateSink(kind, min, fs[0].Class)
		t.Errorf("sequence-dependent candidate %s after %d steps (minimal sequence in the private file)", kind, len(min))
	})
}

// TestSeqSingleStepCensus (AUTHZSEQ_CENSUS=1): every API step kind alone, from the
// fresh world, over actor x subject x scope with the first granted role. It
// explains the single-step bucket of a sweep: which (kind, actor) pairs disagree
// or miss the model when run alone, grouped by class. Prints counts only.
func TestSeqSingleStepCensus(t *testing.T) {
	if os.Getenv("AUTHZSEQ_CENSUS") != "1" {
		t.Skip("set AUTHZSEQ_CENSUS=1")
	}
	counts := map[string]int{}
	for k := skGrant; k <= skGroupRemove; k++ {
		for _, a := range seqActors {
			for _, s := range seqSubjects {
				for _, sc := range seqTargets {
					fs := runSeq(t, []seqStep{{k, a, s, sc, 0, 0}}, nil, nil)
					for _, f := range fs {
						counts[fmt.Sprintf("%s | actor=%s | %s", seqKindNames[k], a, classKind(f.Class))]++
						break
					}
				}
			}
		}
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Logf("CENSUS %s x%d", k, counts[k])
	}
}

// TestSeqOne (AUTHZSEQ_ONE="kind,actor,subject,scope[,role]" with names from
// seqKindNames / principal kinds / A|B|global) prints the findings of one
// single-step sequence, for explaining a census row.
func TestSeqOne(t *testing.T) {
	spec := os.Getenv("AUTHZSEQ_ONE")
	if spec == "" {
		t.Skip("set AUTHZSEQ_ONE")
	}
	f := strings.Split(spec, ",")
	var st seqStep
	for k := range numSeqKinds {
		if seqKindNames[k] == f[0] {
			st.Kind = k
		}
	}
	st.Actor, st.Subject = principalKind(f[1]), principalKind(f[2])
	for _, tg := range seqTargets {
		if tg.String() == f[3] {
			st.T = tg
		}
	}
	if len(f) > 4 {
		n, _ := strconv.Atoi(f[4])
		st.Role = byte(n)
	}
	for _, x := range runSeq(t, []seqStep{st}, nil, nil) {
		t.Logf("ONE %s", x.Class)
	}
}
