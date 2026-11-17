package authzdiff

import (
	"testing"
)

// TestV5extStrictSweep is a deterministic, env-free strict check over the V5EXT
// bindings (ops_v5ext_test.go): riskexception.approve (system.write@global, a
// router-gate differential), riskexception.delete (globalAdminRole, a core-
// enforced creator-or-admin gate) and breakglass.revoke (roles.assign@project
// across REST, gRPC and the model). It runs in ordinary `go test` (skipped under
// -short) so a binding falling out of calibration, or disagreeing with the model
// in a shape no known waiver absorbs, is caught in CI.
//
// Unlike the V8 fast path, breakglass.revoke HAS a gRPC leg, so this drives the
// full runCase (all three legs) for every op — no no-gRPC shortcut.
//
// Coverage: every NAMED principal (admin, viewer, project-admin, no-role, actor-0,
// expired, suspended, restricted-PAT) plus a small CURATED set of gate-boundary
// variations (curatedV5extVariations). The exhaustive generated permission-mask
// space stays with the opt-in TestAuthzDiffSweep and FuzzAuthzDiff; this is the
// fast always-on guard.
//
// Strict rule, verbatim from the full sweep: zero uncalibrated cases and zero
// "unexplained" cases.
func TestV5extStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT strict check drives real core+REST+gRPC legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5extOp(spec.name) {
			continue
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
					for _, cv := range curatedV5extVariations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 20 {
		t.Errorf("only %d cases ran — the curated case space did not run", tally.n)
	}
}

// curatedV5extVariations: gate-boundary cases for a V5EXT op at target t.
//
//   - riskexception.approve: system.write@global gate. Held at global → allowed;
//     absent → denied; held only at a project → denied; via a live group → allowed;
//     a machine (cannot hold a global role) → denied.
//   - riskexception.delete: the gate is an ADMIN role at global scope (creator-or-
//     admin-tier, non-probed creator). No custom role carries the admin bypass, so
//     every custom/machine variation is a NON-holder (denied); only pkGlobalAdmin,
//     a named principal, is allowed. The boundary cases pin that holding
//     system.write@global is NOT enough without the admin role.
//   - breakglass.revoke: roles.assign@project gate. Held at this project → allowed;
//     absent → denied; held only at the other project → denied; via a live group →
//     allowed; a machine holding/ lacking it here → allowed/denied.
func curatedV5extVariations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	switch spec.name {
	case "riskexception.approve":
		have := maskOf([]string{"system.write"})
		return []pv{
			{pkCustom, variation{Mask: have, Route: "user", Scope: "global"}},             // holds system.write@global → allowed
			{pkCustom, variation{Mask: allPerms &^ have, Route: "user", Scope: "global"}}, // lacks it → denied
			{pkCustom, variation{Mask: have, Route: "user", Scope: "A"}},                  // holds it only at A → denied (global required)
			{pkCustom, variation{Mask: have, Route: "group", Scope: "global"}},            // via a live group → allowed
			{pkMachine, variation{Mask: allPerms, Route: "machine", Scope: "A"}},          // machine can't hold a global role → denied
		}
	case "riskexception.delete":
		have := maskOf([]string{"system.write"})
		return []pv{
			{pkCustom, variation{Mask: have, Route: "user", Scope: "global"}},    // system.write@global but no admin role → denied (core: not admin-tier)
			{pkCustom, variation{Mask: allPerms, Route: "user", Scope: "global"}}, // every perm, still no admin bypass → denied
			{pkMachine, variation{Mask: allPerms, Route: "machine", Scope: "A"}},  // machine: never admin-tier → denied
		}
	}
	// breakglass.revoke: project-scope gate (roles.assign@here).
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
