package authzdiff

import (
	"testing"
)

// TestV5bEnvScopedStrictSweep is the always-on (skipped under -short) guard for
// the environment-scoped grant binding (ops_v5b_test.go). It drives every named
// principal plus the environment-scoped custom grants (envVariations) against
// secret.read.env on both projects and both environments, and fails on any
// uncalibrated or "unexplained" case — the same strict rule as the full sweep,
// but deterministic and env-free so it runs in CI.
//
// It additionally PINS the environment-scope behaviour directly
// (TestV5bEnvScope_*), so the guard is one that has been watched to deny the
// cross-environment read, not merely one that "passes": a grant scoped to prod
// authorizes the prod read and is refused for the staging2 read, by the model
// AND by every transport, and vice-versa.
func TestV5bEnvScopedStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5b strict check drives real core+REST+gRPC legs; skipped under -short")
	}
	var spec opSpec
	found := false
	for _, s := range withDerived(t, ops()) {
		if isV5bOp(s.name) {
			spec, found = s, true
		}
	}
	if !found {
		t.Fatal("no V5b env-scoped op found")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, tg := range spec.targets {
		for _, arg := range argsFor(spec) {
			run := func(pk principalKind, v variation) {
				k := caseKey{Op: spec.name, Principal: pk, Target: tg.String(), Arg: arg, variation: v}
				r := runCase(t, spec, k, tg)
				sink.write(r)
				tally.add(t, r)
			}
			for _, pk := range namedPrincipalKinds {
				run(pk, defaultVariation)
			}
			for _, g := range envVariations(spec, tg) {
				run(g.pk, g.v)
			}
		}
	}
	t.Logf("V5b env check: %d cases, %d O1/O2, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5b cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5b cases present: a disagreement no known waiver absorbs")
	}
	if tally.n < 20 {
		t.Errorf("only %d cases ran — the env case space did not run", tally.n)
	}
}

// TestV5bEnvScope_GrantInOneEnvRefusesTheOther is the explicit environment-scope
// assertion. The custom role, held with secrets.read in ONE environment, reads a
// secret in that environment (allowed) and a secret in the OTHER environment of
// the SAME project (refused) — on the model and on every transport leg that
// takes part. This is what makes the strict sweep above non-vacuous.
func TestV5bEnvScope_GrantInOneEnvRefusesTheOther(t *testing.T) {
	if testing.Short() {
		t.Skip("drives real core+REST+gRPC legs; skipped under -short")
	}
	var spec opSpec
	for _, s := range withDerived(t, ops()) {
		if isV5bOp(s.name) {
			spec = s
		}
	}
	have := maskOf([]string{"secrets.read"})
	// For each environment the grant can be pinned to, the matching read is
	// allowed and the cross-environment read is denied.
	cases := []struct {
		grantScope string // "@prod" or "@stg" on project A
		readArg    byte   // 0 = prod secret, 1 = staging2 secret
		wantAllow  bool
	}{
		{"A@prod", 0, true},  // granted in prod, read prod -> allowed
		{"A@prod", 1, false}, // granted in prod, read staging2 -> refused (cross-env)
		{"A@stg", 1, true},   // granted in staging2, read staging2 -> allowed
		{"A@stg", 0, false},  // granted in staging2, read prod -> refused (cross-env)
	}
	for _, c := range cases {
		k := caseKey{Op: spec.name, Principal: pkCustom, Target: tA.String(), Arg: c.readArg,
			variation: variation{Mask: have, Route: "user", Scope: c.grantScope}}
		r := runCase(t, spec, k, tA)
		want := Denied
		if c.wantAllow {
			want = Allowed
		}
		if r.Model != want {
			t.Errorf("model: grant %s read arg=%d: got %s, want %s", c.grantScope, c.readArg, r.Model, want)
		}
		for _, l := range []layer{layerCore, layerREST, layerGRPC} {
			lo := r.Legs[l]
			if lo == nil || lo.NA != "" {
				continue
			}
			if lo.Outcome != want {
				t.Errorf("%s leg: grant %s read arg=%d: got %s (%s), want %s", l, c.grantScope, c.readArg, lo.Outcome, lo.Detail, want)
			}
		}
	}
}
