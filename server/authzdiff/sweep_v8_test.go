package authzdiff

import (
	"testing"
)

// TestV8StrictSweep is a deterministic, env-free strict check over the V8
// bindings (ops_v8_test.go): access-review.campaign.open (roles.assign@project)
// and riskexception.create (system.write@global). Both are pure router-gate
// differentials — the matrix marks their core rows core_refusal:"none", so the
// core leg is recorded but excluded and Oracle 2 compares the REST router gate to
// the independent model. It runs in ordinary `go test` (skipped under -short), so
// a binding falling out of calibration, or disagreeing with the model in a shape
// no known waiver absorbs, is caught in CI.
//
// Coverage: every NAMED principal (admin, viewer, project-admin, no-role, actor-0,
// expired, suspended, restricted-PAT) plus a small CURATED set of gate-boundary
// variations — the custom role (direct and via a live group) holding the gate
// permission at the op's own scope (a holder), without it (a non-holder), and at
// the wrong scope (a non-holder), and the machine principal. The EXHAUSTIVE
// generated permission-mask space stays with the opt-in TestAuthzDiffSweep
// (AUTHZDIFF_OPS=access-review.campaign.open,riskexception.create) and
// FuzzAuthzDiff; this is the fast always-on guard.
//
// Neither V8 op has a gRPC leg (matrix grpc:null), so this drives only the core
// and REST legs and marks the gRPC leg NA by hand via runCaseNoGRPC — exactly
// what runCase records for a spec.grpc==nil op — WITHOUT paying newLeg(layerGRPC)'s
// per-case server startup. TestEveryV8OpHasNoGRPCLeg guards that precondition.
//
// Strict rule, verbatim from the full sweep: zero uncalibrated cases and zero
// "unexplained" cases.
func TestV8StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V8 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV8Op(spec.name) {
			continue
		}
		if spec.grpc != nil {
			t.Fatalf("%s grew a gRPC leg: TestV8StrictSweep skips the gRPC leg and would hide it — drive it through runCase instead", spec.name)
		}
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			for _, tg := range spec.targets {
				for _, arg := range argsFor(spec) {
					if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
						continue
					}
					run := func(pk principalKind, v variation) {
						k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg, variation: v}
						r := runCaseNoGRPC(t, spec, k, tg)
						sink.write(r)
						tally.add(t, r)
					}
					for _, pk := range namedPrincipalKinds {
						run(pk, defaultVariation)
					}
					for _, cv := range curatedV8Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V8 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V8 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V8 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 20 {
		t.Errorf("only %d cases ran — the curated case space did not run", tally.n)
	}
}

// curatedV8Variations: gate-boundary cases for a V8 op at target t, keyed by the
// op's name (not spec.req, whose atP form dereferences the fixtures to resolve the
// project scope). For the scoped-permission op (campaign.open: roles.assign@project)
// the gate perm is held (allowed) or not (denied) at the op's own scope, and
// holding it at the OTHER project is a non-holder here. For the global op
// (riskexception.create: system.write@global) the gate perm must be held at GLOBAL
// scope; held at a project is a non-holder. The machine principal is included.
func curatedV8Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	if spec.name == "riskexception.create" {
		have := maskOf([]string{"system.write"})
		return []pv{
			{pkCustom, variation{Mask: have, Route: "user", Scope: "global"}},             // holds system.write@global → allowed
			{pkCustom, variation{Mask: allPerms &^ have, Route: "user", Scope: "global"}}, // lacks it → denied
			{pkCustom, variation{Mask: have, Route: "user", Scope: "A"}},                  // holds it only at A → denied (global required)
			{pkCustom, variation{Mask: have, Route: "group", Scope: "global"}},            // via a live group → allowed
			{pkMachine, variation{Mask: allPerms, Route: "machine", Scope: "A"}},          // machine can't hold a global role → denied
		}
	}
	// campaign.open: project-scope gate (roles.assign@here).
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	have := maskOf([]string{"roles.assign"})
	return []pv{
		{pkCustom, variation{Mask: have, Route: "user", Scope: here}},                 // holds roles.assign@here → allowed
		{pkCustom, variation{Mask: allPerms &^ have, Route: "user", Scope: here}},     // lacks it → denied
		{pkCustom, variation{Mask: have, Route: "user", Scope: other}},                // holds it only at the other project → denied here
		{pkCustom, variation{Mask: have, Route: "group", Scope: here}},                // via a live group → allowed
		{pkMachine, variation{Mask: have, Route: "machine", Scope: here}},             // machine holds it here → allowed
		{pkMachine, variation{Mask: allPerms &^ have, Route: "machine", Scope: here}}, // machine lacks it → denied
	}
}

// TestEveryV8OpHasNoGRPCLeg guards runCaseNoGRPC's precondition: if any V8 op
// gains a gRPC binding, the fast check above would skip a real leg. This test
// fails first, forcing that op onto the full runCase path.
func TestEveryV8OpHasNoGRPCLeg(t *testing.T) {
	for _, s := range v8Ops() {
		if s.grpc != nil {
			t.Errorf("%s has a gRPC leg: move it off TestV8StrictSweep's no-gRPC fast path", s.name)
		}
	}
}
