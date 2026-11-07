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
	limited := seqRateLimited.Load()
	for i, steps := range list {
		fs := runSeq(t, steps, nil, nil)
		for _, f := range fs {
			t.Errorf("control %d: step %d: %s", i, f.Step, f.Class)
		}
	}
	requireNoRateLimited(t, limited)
}

// requireNoRateLimited fails when a probe hit the invalid-token limiter since
// before was read: such a probe is recorded as n/a and checked nothing, so a
// control or plant run that has one proves less than it claims.
func requireNoRateLimited(t *testing.T, before int64) {
	t.Helper()
	if n := seqRateLimited.Load() - before; n > 0 {
		t.Errorf("%d probe(s) hit the invalid-token rate limiter and checked nothing", n)
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
		{
			fault: seqFault{name: "step-5xx", step: func(l layer, st seqStep, lg *leg, o *legOutcome) *legOutcome {
				if l == layerREST && st.Kind == skRevoke {
					return &legOutcome{Outcome: Other, Detail: "planted-500"}
				}
				return o
			}},
			steps: []seqStep{{skGrant, pkGlobalAdmin, pkNone, tA, 0, 0}, {skRevoke, pkGlobalAdmin, pkNone, tA, 0, 0}},
			class: "O-S:other",
		},
		{
			// The revoke does nothing on every leg, and the grant it targets is a
			// fixture one, so the failing step alone reproduces the class: only the
			// always-fail rule keeps the fuzz verdict from calling it single-step.
			fault: seqFault{name: "revoke-noop-held-grant", skipDo: func(l layer, st seqStep) bool { return st.Kind == skRevoke }},
			steps: []seqStep{{skRevoke, pkGlobalAdmin, pkViewer, tA, 0, 0}},
			class: "O-E:revoked-row-still-present",
		},
	}
}

// TestSeqClassKey: the class key keeps the direction, and only a class where a
// transport allows against the model, the other legs or the state is an
// over-allow.
func TestSeqClassKey(t *testing.T) {
	a := "O-S:step-vs-model(role.grant admin->none;got=allowed;model=denied)"
	b := "O-S:step-vs-model(role.grant admin->none;got=denied;model=allowed)"
	if classKey(a) == classKey(b) {
		t.Fatalf("opposite directions share the key %q", classKey(a))
	}
	if classKey(a) != "O-S:step-vs-model(got=allowed;model=denied)" {
		t.Fatalf("unexpected key %q", classKey(a))
	}
	for c, want := range map[string]bool{
		a: true, b: false,
		"O-P:allowed-but-model-denies(x;rest)":                        true,
		"O-P:over-denial(x;rest)":                                     false,
		"O-E:denied-step-changed-state(x;grpc)":                       true,
		"O-S:layers-disagree(x;allow=core;deny=rest+grpc)":            false,
		"O-S:layers-disagree(x;allow=rest;deny=core)":                 true,
		"O-P:layers-disagree(x;allow=core+grpc;deny=rest)":            true,
		"O-S:other(x;other=rest;got=allowed;model=allowed)":           false,
		"O-E:revoked-row-still-present(x;rest)":                       false,
		"O-S:layers-disagree(x;allow=core;deny=rest) # no allow=rest": false,
	} {
		if got := isOverAllow(c); got != want {
			t.Errorf("isOverAllow(%q) = %v, want %v", c, got, want)
		}
	}
	// Every O-E class always fails, even though only some are over-allows.
	for c, want := range map[string]bool{
		"O-E:revoked-row-still-present(x;rest)":            true,
		"O-E:account-state-not-suspended(x;core)":          true,
		"O-E:group-row-still-present(x;grpc)":              true,
		"O-E:granted-row-missing(x;rest)":                  true,
		"O-E:reactivated-user-cannot-log-in(x;core)":       true,
		"O-E:denied-step-changed-state(x;grpc)":            true,
		"O-S:layers-disagree(x;allow=core;deny=rest+grpc)": false,
		"O-P:over-denial(x;rest)":                          false,
	} {
		if got := alwaysFails(c); got != want {
			t.Errorf("alwaysFails(%q) = %v, want %v", c, got, want)
		}
	}
}

// seqDefaultPlant is the plant that runs in the default `go test`, so the
// oracles are watched failing in CI; AUTHZSEQ_SELFTEST=1 runs all of them
// (about 8 s).
const seqDefaultPlant = "revoke-noop"

func TestSeqPlantsAreDetected(t *testing.T) {
	all := os.Getenv("AUTHZSEQ_SELFTEST") == "1"
	for _, pl := range seqPlants() {
		t.Run(pl.fault.name, func(t *testing.T) {
			if !all && pl.fault.name != seqDefaultPlant {
				t.Skip("set AUTHZSEQ_SELFTEST=1")
			}
			limited := seqRateLimited.Load()
			defer requireNoRateLimited(t, limited)
			if clean := runSeq(t, pl.steps, nil, nil); len(clean) != 0 {
				t.Fatalf("sequence is not clean without the plant: %v", clean)
			}
			fs := runSeq(t, pl.steps, &pl.fault, nil)
			found := false
			for _, f := range fs {
				found = found || classKind(f.Class) == pl.class
			}
			if !found {
				t.Fatalf("plant %s not detected as %s; findings=%v", pl.fault.name, pl.class, fs)
			}
			// The oracle firing is not enough: the verdict the fuzzer applies must fail.
			if v := seqVerdict(t, pl.steps, fs, &pl.fault, 30); !v.Fail {
				t.Fatalf("plant %s is detected as %s but the fuzz verdict is %q, not a failure", pl.fault.name, pl.class, v.Kind)
			}
		})
	}
}

// seqVerdict is the one triage of a sequence whose run produced findings fs: the
// fuzz body, the sweep and the plant tests all use it, so what the self-test
// proves fails is what the fuzzer fails. Kinds: "" (no findings), "always-fail"
// (alwaysFails class after shrinking), "single-step" (the failing step alone, from
// a fresh world and without the fault, reproduces the class: logged, not counted)
// and "candidate" (sequence-dependent). Fail is true for always-fail and candidate.
type seqVerdictResult struct {
	Kind string
	Fail bool
	Key  string
	Min  []seqStep
	Top  seqFinding
}

func seqVerdict(tb testing.TB, steps []seqStep, fs []seqFinding, fault *seqFault, budget int) seqVerdictResult {
	if len(fs) == 0 {
		return seqVerdictResult{}
	}
	// Cheap first: the failing step alone reproduces the class, so there is
	// nothing to shrink.
	if top := pickFinding(fs); isSingleStep(tb, steps, top) {
		return seqVerdictResult{Kind: "single-step", Key: classKey(top.Class), Min: steps, Top: top}
	}
	min := shrink(tb, steps, fault, budget)
	fs = runSeq(tb, min, fault, nil)
	if len(fs) == 0 {
		return seqVerdictResult{}
	}
	top := pickFinding(fs)
	v := seqVerdictResult{Key: classKey(top.Class), Min: min, Top: top}
	switch {
	case alwaysFails(top.Class):
		v.Kind, v.Fail = "always-fail", true
	// With a fault injected the replay below runs without it, so a one-step
	// minimal sequence is not proof of single-step behaviour.
	case (len(min) == 1 && fault == nil) || isSingleStep(tb, min, top):
		v.Kind = "single-step"
	default:
		v.Kind, v.Fail = "candidate", true
	}
	return v
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
	limited0 := seqRateLimited.Load()
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
		v := seqVerdict(t, steps, fs, nil, 40)
		switch v.Kind {
		case "single-step":
			singleStep++
			byClass["single-step:"+v.Key]++
		case "always-fail":
			byClass["ALWAYS-FAIL:"+v.Key]++
			privateSink(v.Key, v.Min, v.Top.Class)
			t.Errorf("%s after %d steps (minimal sequence in the private file)", v.Key, len(v.Min))
		case "candidate":
			byClass["CANDIDATE:"+v.Key]++
			privateSink(v.Key, v.Min, v.Top.Class)
		}
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
	t.Logf("SEQ-SWEEP sequences=%d steps=%d probes=%d rate-limited=%d elapsed=%s single-step=%d", ran, stats.steps, stats.probes, seqRateLimited.Load()-limited0, time.Since(start).Round(time.Second), singleStep)
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
		v := seqVerdict(t, steps, runSeq(t, steps, nil, nil), nil, 30)
		switch v.Kind {
		case "single-step":
			t.Logf("single-step %s", v.Key)
		case "always-fail":
			privateSink(v.Key, v.Min, v.Top.Class)
			t.Errorf("%s after %d steps (minimal sequence in the private file)", v.Key, len(v.Min))
		case "candidate":
			privateSink(v.Key, v.Min, v.Top.Class)
			t.Errorf("sequence-dependent candidate %s after %d steps (minimal sequence in the private file)", v.Key, len(v.Min))
		}
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
