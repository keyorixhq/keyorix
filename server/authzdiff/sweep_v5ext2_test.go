package authzdiff

import (
	"testing"
)

// TestV5ext2StrictSweep is a deterministic, env-free strict check over the
// V5EXT2 bindings (ops_v5ext2_test.go): accessreview.attest, accessreview.revoke,
// campaign.decide, campaign.close, and breakglass.review.
//
// All five ops have no gRPC leg (matrix.json grpc=null for each). The oracle
// signal is REST vs model only; core legs are either excluded by ID-2
// (campaign.close, core_refusal:"none") or by coreGateExcluded (the other four).
//
// Curated variations cover the roles.read@project gate (attest) and
// roles.assign@project gate (revoke, review), and their group/machine forms.
// Campaign ops (campaign.decide and campaign.close) use campaignProjectID as
// scope, which is outside the standard variation scope tokens (A/B); they run
// named principals only — the global admin (and any principal that happens to
// hold a global role) passes through, everything else is denied consistently.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext2StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT2 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext2Op(spec.name) {
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
					for _, cv := range curatedV5ext2Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT2 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT2 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT2 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 10 {
		t.Errorf("only %d cases ran — the curated case space did not run", tally.n)
	}
}

// curatedV5ext2Variations: gate-boundary cases for a V5EXT2 op at target t.
//
//   - accessreview.attest: roles.read@project gate (coreGateExcluded, humanOnly).
//     Human holds/lacks/scoped-to-other/via-group; machine holds/lacks.
//   - accessreview.revoke, breakglass.review: roles.assign@project gate (same shape).
//   - campaign.decide, campaign.close: scope is campaignProjectID — outside the
//     standard A/B variation tokens. Named principals only; no curated variations.
func curatedV5ext2Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	switch spec.name {
	case "campaign.decide", "campaign.close":
		// campaignProjectID is not a standard variation scope token.
		// Named principals are the only source of gate-boundary cases here.
		return nil
	}

	// For attest: roles.read; for revoke/review: roles.assign.
	perm := "roles.assign"
	if spec.name == "accessreview.attest" {
		perm = "roles.read"
	}
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	have := maskOf([]string{perm})
	return []pv{
		{pkCustom, variation{Mask: have, Route: "user", Scope: here}},                 // holds perm@here → allowed
		{pkCustom, variation{Mask: allPerms &^ have, Route: "user", Scope: here}},     // lacks it → denied
		{pkCustom, variation{Mask: have, Route: "user", Scope: other}},                // holds only at other project → denied here
		{pkCustom, variation{Mask: have, Route: "group", Scope: here}},                // via live group → allowed
		{pkMachine, variation{Mask: have, Route: "machine", Scope: here}},             // machine holds it → denied (humanOnly)
		{pkMachine, variation{Mask: allPerms &^ have, Route: "machine", Scope: here}}, // machine lacks it → denied
	}
}
