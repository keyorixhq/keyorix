package authzdiff

import (
	"testing"
)

// TestV5b1StrictSweep is a deterministic, env-free strict check over the V5B1
// bindings (ops_v5b1_test.go). It runs the named principals AND the generated
// permission-set variations (genVariations) so the secrets.write RBAC boundary
// is exercised in both directions, not just by the hand-picked principals.
//
// secret.classify (plan rule 7 "classify-actor"):
//
//	Gate permSecretsWrite, resolved per-secret (RequireScopedSecretPermission,
//	router.go:812) — identical to the covered secret.update op. Core ClassifySecret
//	performs no authorization (core_refusal="none" → coreEnforced=false → the core
//	leg is excluded from both oracles; the route gate enforces).
//	Positive control: the global admin (owns every fixture secret and bypasses
//	permission checks) — the normal admin control, no controlAs needed.
//
// Oracle direction (deny-first, EXTENSION-PLAN.md §6 B1): the only class that
// signals a real defect is O2:allowed-but-model-denies — the model denies
// (no secrets.write at the secret's project) and the product performs the
// classification change anyway. The opposite direction (model allows, product
// refuses = O2:over-denial) is a false positive until the admin positive control
// passes; here it does, and the model mirrors secret.update's already-calibrated
// requirement, so over-denials do not arise for the probed principals.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
//
// What this check does NOT verify: see ops_v5b1_test.go's secret.classify doc
// comment (no downgrade re-gate, no persistence check, args 1-3 Oracle-1 only,
// no gRPC leg).
func TestV5b1StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5B1 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5b1Op(spec.name) {
			continue
		}
		spec := spec
		t.Run(spec.name, func(t *testing.T) {
			probe := newLeg(t, layerCore)
			defer probe.close()
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
					for _, g := range genVariations(requirementPerms(probe, spec, tg, arg), tg) {
						run(g.pk, g.v)
					}
				}
			}
		})
	}
	t.Logf("V5B1 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5B1 cases: the admin positive control was not allowed — fix the op binding or the fixture", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5B1 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 4 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}
