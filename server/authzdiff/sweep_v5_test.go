package authzdiff

import "testing"

// TestV5StrictSweep is a deterministic, env-free strict check over the V5
// break-glass-activation binding (ops_v5_test.go). It runs in ordinary `go test`
// (skipped under -short), so the binding falling out of calibration, or
// disagreeing with the model in a shape no known waiver absorbs, is caught in
// CI. reassign-owner, the earlier V5 area, is left out to keep the check fast;
// it runs in the opt-in full sweep and TestAuthzDiffSmoke. Neither of those, nor
// this test, FAILS when only reassign-owner's own core gate is removed: REST
// still gates that route, so the core-only over-allow lands in the known-04
// waiver (partition_test.go). Its plant asserts exactly that recording.
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
// Each case runs through runCase, the same oracle as the full sweep, on all
// three legs (core, REST and the BreakGlassService.ActivateBreakGlass gRPC RPC).
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
			continue // reassign-owner runs in the full sweep and TestAuthzDiffSmoke; keep this fast
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
						r := runCase(t, spec, k, tg)
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

func isBreakGlassV5Op(name string) bool {
	for _, s := range v5BreakGlassOps() {
		if s.name == name {
			return true
		}
	}
	return false
}
