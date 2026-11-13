package authzdiff

import (
	"fmt"
	"testing"
)

// TestV5StrictSweep is a deterministic, env-free strict check over the V5
// break-glass-activation binding (ops_v5_test.go). It runs in ordinary `go test`
// (skipped under -short), so the binding falling out of calibration, or
// disagreeing with the model in a shape no known waiver absorbs, is caught in
// CI. (reassign-owner, the earlier V5 area, is already guarded by its own plant
// and TestAuthzDiffSmoke; keeping it out of this test keeps the check fast.)
//
// Coverage: every NAMED principal (admin, viewer, project-admin, no-role,
// actor-0, expired, suspended, restricted-PAT) plus a small CURATED set of
// membership variations — the custom role held directly or via a live GROUP at
// this project (a member) and at the OTHER project (a non-member here), and the
// machine principal. These are the distinctions break-glass's membership gate
// turns on. The EXHAUSTIVE generated permission-mask space stays with the opt-in
// TestAuthzDiffSweep (AUTHZDIFF_SWEEP=1) and FuzzAuthzDiff; this test is the fast
// always-on guard, deliberately bounded so default `go test` does not pay the
// full sweep's cost.
//
// Break-glass has NO gRPC leg (it is left to a later area), so this drives only
// the core and REST legs and marks the gRPC leg NA by hand — exactly what
// runCase records for a spec.grpc==nil op — WITHOUT paying newLeg(layerGRPC)'s
// per-case gRPC-server startup. TestEveryV5OpHasNoGRPCLeg guards that
// precondition: the moment a V5 op grows a gRPC binding this fast path would
// skip a real leg, and that test fails first.
//
// Strict rule, verbatim from the full sweep: zero uncalibrated cases and zero
// "unexplained" cases. Disagreements that map to a known waiver (the
// suspended-account known-02; the machine validation-refusal known-09 that
// break-glass activation produces) are allowed, exactly as in the full sweep.
func TestV5StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isBreakGlassV5Op(spec.name) {
			continue // reassign-owner is already guarded (its plant + TestAuthzDiffSmoke); keep this fast
		}
		if spec.grpc != nil {
			t.Fatalf("%s grew a gRPC leg: TestV5StrictSweep skips the gRPC leg and would hide it — drive it through runCase instead", spec.name)
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
					for _, cv := range curatedV5Variations(tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 20 {
		t.Errorf("only %d cases ran — the curated case space did not run", tally.n)
	}
}

// curatedV5Variations: membership-relevant cases for a target. "group"/"user"
// routes at the target's own scope confer membership there; at the other
// project they do not. The machine principal (always refused with a validation
// error at core, known-09) is included once per target.
func curatedV5Variations(t tgt) []struct {
	pk principalKind
	v  variation
} {
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	return []struct {
		pk principalKind
		v  variation
	}{
		{pkCustom, variation{Mask: allPerms, Route: "group", Scope: here}},  // group member here
		{pkCustom, variation{Mask: allPerms, Route: "group", Scope: other}}, // group member elsewhere → non-member here
		{pkCustom, variation{Mask: allPerms, Route: "user", Scope: other}},  // direct member elsewhere → non-member here
		{pkMachine, variation{Mask: allPerms, Route: "machine", Scope: here}},
	}
}

// runCaseNoGRPC is runCase for an op with no gRPC leg: it drives the core and
// REST legs, records the gRPC leg NA (as runCase would for spec.grpc==nil), and
// runs the identical uncalibration, classification and partition steps.
func runCaseNoGRPC(tb testing.TB, spec opSpec, k caseKey, t tgt) *caseResult {
	tb.Helper()
	_, fx := template(tb)
	p := fx.principals[k.Principal]
	res := &caseResult{caseKey: k, Legs: map[layer]*legOutcome{}}
	res.Legs[layerCore] = runLayer(tb, spec, layerCore, p, k, t, res)
	res.Legs[layerREST] = runLayer(tb, spec, layerREST, p, k, t, nil)
	res.Legs[layerGRPC] = &legOutcome{NA: "ID-3: no gRPC RPC (ADR-105 partial surface)"}
	for l, lo := range res.Legs {
		if lo.NA != "" {
			continue
		}
		if c := control(tb, spec, l, t, k.Arg); c.NA == "" && c.Outcome != Allowed {
			lo.NA = fmt.Sprintf("uncalibrated: admin control on %s got %s (%s)", l, c.Outcome, c.Detail)
		}
	}
	res.Classes = classify(spec, p, res)
	res.PATUngatedWrite = patRefusesUngatedWrite(tb, fx, spec, p)
	res.Bucket = explain(res)
	return res
}

func isBreakGlassV5Op(name string) bool {
	for _, s := range v5BreakGlassOps() {
		if s.name == name {
			return true
		}
	}
	return false
}

// TestEveryV5OpHasNoGRPCLeg guards runCaseNoGRPC's precondition: if any V5 op
// gains a gRPC binding, the fast check above would skip a real leg. This test
// fails first, forcing that op onto the full runCase path.
func TestEveryV5OpHasNoGRPCLeg(t *testing.T) {
	for _, s := range v5Ops() {
		if s.grpc != nil {
			t.Errorf("%s has a gRPC leg: move it off TestV5StrictSweep's no-gRPC fast path", s.name)
		}
	}
}
