package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext7StrictSweep is a deterministic, env-free strict check over the
// V5EXT7 schedule bindings (ops_v5ext7_test.go):
//
//	secret.schedule.set: secrets.manage. Core: coreGateExcluded (SetSecretSchedule has
//	  no actorID — cannot check actor state; see HARDENING-2). REST only.
//	  Curated: manage → allowed; write-only → denied.
//
//	secret.schedule.delete: same as schedule.set.
//
// What this oracle does NOT verify:
//   - secret.schedule.*: temporal effect (whether the schedule actually restricts
//     access); LogSecretScheduleSet / LogSecretScheduleDeleted audit events.
//   - a suspended-actor refusal on either op (HARDENING-2: no core gate exists).
//   - WebAuthn or MFA-step-up gate on either op.
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
	if tally.n < 2 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext7Variations returns gate-boundary cases for the V5EXT7 schedule ops:
// route gate secrets.manage. A user holding secrets.manage → allowed; a user holding
// secrets.write but not secrets.manage → denied.
func curatedV5ext7Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	here := "A"
	if t == tB {
		here = "B"
	}
	switch spec.name {
	case "secret.schedule.set", "secret.schedule.delete":
		manage := maskOf([]string{"secrets.manage"})
		writeOnly := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: manage, Route: "user", Scope: here}},    // manage → allowed
			{pkCustom, variation{Mask: writeOnly, Route: "user", Scope: here}}, // write-only (no manage) → denied
		}
	}
	return nil
}

// TestSecretScheduleRouterGatesPresent asserts that the schedule PUT and DELETE
// route registrations in server/http/router.go exactly match what this sweep
// tests. Fails immediately if either gate registration is removed or changed,
// turning a silent coverage loss into a build failure.
//
// What this does NOT verify: that the gate is applied to the correct HTTP method
// (a method-swap would need an integration test hitting the route), nor that the
// middleware refuses at runtime (it is a source-text anchor, so a reformat or an
// alias rename breaks it without any behaviour change).
func TestSecretScheduleRouterGatesPresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	for _, anchor := range []string{
		`r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Put(pathIDSchedule, secretHandler.SetSecretSchedule)`,
		`r.With(customMiddleware.RequireScopedSecretPermission(permSecretsManage, "id")).Delete(pathIDSchedule, secretHandler.DeleteSecretSchedule)`,
	} {
		if n := strings.Count(string(src), anchor); n != 1 {
			t.Errorf("schedule router gate anchor found %d times (want 1): %q", n, anchor)
		}
	}
}

// TestSecretClassifyRouterGatePresent asserts that the classify PATCH route
// registration in server/http/router.go exactly matches what this sweep tests.
//
// What this does NOT verify: the SecretActionClassify argument value, which is
// asserted by the core layer's own action-constant tests, nor runtime enforcement.
func TestSecretClassifyRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.RequireScopedSecretPermission(permSecretsWrite, "id", core.SecretActionClassify)).Patch("/{id}/classification", secretHandler.ClassifySecret)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("classify router gate anchor found %d times (want 1): %q", n, anchor)
	}
}
