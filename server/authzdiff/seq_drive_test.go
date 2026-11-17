package authzdiff

import (
	"fmt"
	"math/rand"
	"os"
	"slices"
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
			// a revoke of a grant the viewer holds in the fixture that no leg
			// carries out: every leg agrees, the model (reading the same tables)
			// agrees, and the failing step alone reproduces it, so only an O-E
			// class that always fails catches it
			fault: seqFault{name: "revoke-noop-held-grant", skipDo: func(l layer, st seqStep) bool { return st.Kind == skRevoke }},
			steps: []seqStep{{skRevoke, pkGlobalAdmin, pkViewer, tA, 0, 0}},
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
	// every over-allow, every O-E intent class and O-S:other always fail; the
	// two known single-step behaviours (SEQUENCE.md) do not
	for c, want := range map[string]bool{
		a: true, b: false,
		"O-E:denied-step-changed-state(x;grpc)":                   true,
		"O-E:revoked-row-still-present(x;core)":                   true,
		"O-E:granted-row-missing(x;rest)":                         true,
		"O-E:account-state-not-suspended(x;grpc)":                 true,
		"O-E:account-state-not-active(x;rest)":                    true,
		"O-E:group-row-missing(x;core)":                           true,
		"O-E:group-row-still-present(x;rest)":                     true,
		"O-E:reactivated-user-cannot-log-in(x;grpc)":              true,
		"O-S:other(x;other=rest;got=allowed;model=allowed)":       true,
		"O-S:layers-disagree(x;allow=core;deny=rest)":             false,
		"O-P:over-denial(x;rest)":                                 false,
		"O-S:step-vs-model(role.revoke;got=denied;model=allowed)": false,
	} {
		if got := alwaysFails(c); got != want {
			t.Errorf("alwaysFails(%q) = %v, want %v", c, got, want)
		}
	}
}

// TestSeqClientErrorSplit: only a transport's client error keeps an Other step
// out of the always-failing O-S:other; an unknown detail is a server error.
func TestSeqClientErrorSplit(t *testing.T) {
	for _, c := range []struct {
		l      layer
		detail string
		want   bool
	}{
		{layerREST, "Bad Request", true},
		{layerREST, "Conflict", true},
		{layerREST, "Unprocessable Entity", true},
		{layerREST, "Internal Server Error", false},
		{layerREST, "Service Unavailable", false},
		{layerREST, "planted-500", false},
		{layerREST, "", false},
		{layerGRPC, "InvalidArgument", true},
		{layerGRPC, "AlreadyExists", true},
		{layerGRPC, "FailedPrecondition", true},
		{layerGRPC, "Internal", false},
		{layerGRPC, "Unknown", false},
		{layerGRPC, "Unavailable", false},
		{layerGRPC, "Bad Request", false},
		{layerCore, "untyped-error", false},
	} {
		if got := isClientError(c.l, &legOutcome{Outcome: Other, Detail: c.detail}); got != c.want {
			t.Errorf("isClientError(%s, %q) = %v, want %v", c.l, c.detail, got, c.want)
		}
	}
	if alwaysFails("O-S:other-client(x;other=rest+grpc;got=other;model=allowed)") {
		t.Error("O-S:other-client always fails")
	}
}

// TestSeqRoleGrantAnswersAreClientErrors (#4020, fixed): a grant repeated in the
// sequence (REST 409, gRPC AlreadyExists) and a revoke of a grant the subject
// does not hold (REST 404, gRPC NotFound) are client answers on every transport.
// Neither is a server error any more, so neither is an always-failing O-S:other
// and neither fails a fuzz run or a sweep. The repeated grant is no finding at
// all (the expected conflict, state unchanged); the revoke of an absent grant is
// the single-step step-vs-model denial of SEQUENCE.md.
func TestSeqRoleGrantAnswersAreClientErrors(t *testing.T) {
	grant := seqStep{skGrant, pkGlobalAdmin, pkNone, tA, 0, 0}
	revoke := seqStep{skRevoke, pkGlobalAdmin, pkNone, tA, 0, 0}
	for name, steps := range map[string][]seqStep{
		"repeated grant":   {grant, grant},
		"revoke of absent": {revoke},
	} {
		fs := runSeq(t, steps, nil, nil)
		if name == "revoke of absent" && len(fs) == 0 {
			t.Fatalf("%s: expected the step-vs-model denial, got no finding", name)
		}
		for _, f := range fs {
			if classKind(f.Class) == "O-S:other" {
				t.Errorf("%s: %q is a server-error answer; the gRPC mapping must give a client error", name, f.Class)
			}
		}
		if v := seqVerdict(t, steps, nil, nil); v.fail() {
			t.Errorf("%s: verdict=%d key=%s fails the run", name, v.kind, v.key)
		}
	}
}

// seqDefaultPlants run in the default `go test`, so the oracles and the triage
// are watched failing in CI; AUTHZSEQ_SELFTEST=1 runs all of them (about 10 s).
var seqDefaultPlants = map[string]bool{"revoke-noop": true, "revoke-noop-held-grant": true}

// TestSeqPlantsAreDetected: each plant is seen by its oracle class, and the
// triage FuzzAuthzSeq and the sweep use (seqVerdict) fails the run on it.
func TestSeqPlantsAreDetected(t *testing.T) {
	all := os.Getenv("AUTHZSEQ_SELFTEST") == "1"
	for _, pl := range seqPlants() {
		t.Run(pl.fault.name, func(t *testing.T) {
			if !all && !seqDefaultPlants[pl.fault.name] {
				t.Skip("set AUTHZSEQ_SELFTEST=1")
			}
			limited := seqRateLimited.Load()
			defer requireNoRateLimited(t, limited)
			if clean := runSeq(t, pl.steps, nil, nil); len(clean) != 0 {
				t.Fatalf("sequence is not clean without the plant: %v", clean)
			}
			fs := runSeq(t, pl.steps, &pl.fault, nil)
			if !slices.ContainsFunc(fs, func(f seqFinding) bool { return classKind(f.Class) == pl.class }) {
				t.Fatalf("plant %s not detected as %s; findings=%v", pl.fault.name, pl.class, fs)
			}
			if v := seqVerdict(t, pl.steps, &pl.fault, nil); !v.fail() {
				t.Fatalf("plant %s detected as %s but the triage does not fail the run: verdict=%d key=%s", pl.fault.name, pl.class, v.kind, v.key)
			}
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
	limited0 := seqRateLimited.Load()
	start := time.Now()
	byClass := map[string]int{}
	singleStep := 0
	ran := 0
	first, _ := strconv.Atoi(os.Getenv("AUTHZSEQ_START"))
	for i := first; i < first+n && time.Since(start) < capD; i++ {
		steps := genSeq(rand.New(rand.NewSource(int64(seed*1_000_000 + i))))
		v := seqVerdict(t, steps, nil, stats)
		ran++
		switch v.kind {
		case seqSingleStep:
			singleStep++
			byClass["single-step:"+v.key]++
		case seqAlwaysFail:
			byClass["ALWAYS-FAIL:"+v.key]++
			privateSink(v.key, v.min, v.class)
			t.Errorf("always-fail class %s after %d steps (minimal sequence in the private file)", v.key, len(v.min))
		case seqCandidate:
			byClass["CANDIDATE:"+v.key]++
			privateSink(v.key, v.min, v.class)
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
	// mask is the swarm feature mask (first fuzz argument): it selects the subset
	// of the step-kind alphabet this execution may use (internal/fuzzutil.Swarm).
	// Every pre-swarm seed keeps its meaning by prepending an all-ones mask —
	// "every kind available", i.e. the uniform generator.
	const allKinds = ^uint64(0)
	f.Add(allKinds, []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0})
	f.Add(allKinds, []byte{2, 0, 1, 0, 0, 3, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, mask uint64, data []byte) {
		v := seqVerdict(t, decodeSeqSwarm(mask, data), nil, nil)
		switch v.kind {
		case seqSingleStep:
			t.Logf("single-step %s", v.key)
		case seqAlwaysFail:
			privateSink(v.key, v.min, v.class)
			t.Errorf("always-fail class %s after %d steps (minimal sequence in the private file)", v.key, len(v.min))
		case seqCandidate:
			privateSink(v.key, v.min, v.class)
			t.Errorf("sequence-dependent candidate %s after %d steps (minimal sequence in the private file)", v.key, len(v.min))
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
