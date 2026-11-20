package authzdiff

import (
	"testing"
)

// TestV5ext7StrictSweep is a deterministic, env-free strict check over the
// V5EXT7 group of operations (see isV5ext7Op for the full list).
//
// V5EXT7 step 1 — phase5 share write ops (already bound; coreEnforced and
// strict sweep added here):
//
//	share.revoke: secrets.write + (owner OR secrets.manage). Core: requireActorActive
//	  + requireShareAuthority + revokerMayManageSecret. gRPC and REST.
//	  Positive control: pkAdmin (owner).
//	  Curated: custom user with both write+manage → allowed (non-owner manager
//	    path); custom with write-only → denied; machine → denied (p.machineID==0 gate).
//
//	share.update: secrets.write + (owner only). Core: requireActorActive +
//	  requireShareAuthority (owner-only, no alternative). gRPC and REST.
//	  Positive control: pkAdmin (owner).
//	  Curated: custom with secrets.write but not owner → denied.
//
//	share.self.remove: recipient-only (pkViewer and pkCustom). No RBAC gate.
//	  Core: RemoveSelfFromShare checks membership. REST only. Target: tA only.
//	  Positive control: pkViewer.
//
// What this oracle does NOT verify:
//   - share.self.remove: RBAC gate (there is none; the only gate is recipient membership).
//   - WebAuthn or MFA-step-up gate on any of these ops.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext7StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT7 strict sweep drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext7Op(spec.name) {
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
					for _, cv := range curatedV5ext7Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT7 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT7 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT7 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 5 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext7Variations returns gate-boundary cases for V5EXT7 ops.
//
//   - share.revoke: holds secrets.write+manage (non-owner manager path allowed);
//     holds write-only (non-owner, denied at core); machine holds both (denied:
//     model p.machineID==0 gate); via group with both (allowed).
//   - share.update: holds write but not owner (denied at core); via group not owner
//     (denied); machine holds write (denied — machine cannot be ownerUserID).
//   - share.self.remove: no curated RBAC cases (no RBAC gate; boundary is recipient).
func curatedV5ext7Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	_ = other

	switch spec.name {
	case "share.revoke":
		// Gate: secrets.write required by route; core additionally requires owner
		// OR secrets.manage (revokerMayManageSecret). Machine: p.machineID!=0
		// means revokerMayManageSecret always returns false, so denied even with both.
		writeManage := maskOf([]string{"secrets.write", "secrets.manage"})
		writeOnly := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: writeManage, Route: "user", Scope: here}},     // non-owner + manage → allowed
			{pkCustom, variation{Mask: writeOnly, Route: "user", Scope: here}},       // non-owner, write only → denied
			{pkCustom, variation{Mask: writeManage, Route: "group", Scope: here}},    // via group + manage → allowed
			{pkMachine, variation{Mask: writeManage, Route: "machine", Scope: here}}, // machine → denied (p.machineID!=0)
		}
	case "share.update":
		// Gate: secrets.write required by route; core requires owner-only
		// (requireShareAuthority, no ownerOrPerm alternative). Any non-admin denied.
		write := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: write, Route: "user", Scope: here}},              // non-owner holds write → denied
			{pkCustom, variation{Mask: allPerms &^ write, Route: "user", Scope: here}},  // lacks write → denied
			{pkCustom, variation{Mask: write, Route: "group", Scope: here}},             // via group, non-owner → denied
			{pkMachine, variation{Mask: write, Route: "machine", Scope: here}},          // machine → denied (not owner)
		}
	case "share.self.remove":
		// No RBAC gate; authorization is entirely by recipient membership.
		return nil
	}
	return nil
}

// isV5ext7Op reports whether name is covered by TestV5ext7StrictSweep.
// Updated incrementally across V5EXT7 steps.
func isV5ext7Op(name string) bool {
	switch name {
	case
		// V5EXT7 step 1: phase5 share write ops
		"share.revoke", "share.update", "share.self.remove":
		return true
	}
	return false
}
