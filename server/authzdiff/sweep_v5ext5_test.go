package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext5StrictSweep is a deterministic, env-free strict check over the
// V5EXT5 bindings (ops_v5ext5_test.go): mfa.activate, mfa.disable, and
// mfa.recovery-codes.regenerate.
//
// mfa.activate:
//
//	No RBAC gate. Core: ActivateMFA checks pending enrollment (coreGateExcluded).
//	Positive control: pkMFAEnrollee (the only principal with a pending enrollment).
//	Named principals include pkMFAEnrollee (world_test.go V5EXT5 seed).
//
// mfa.disable:
//
//	No RBAC gate. Core: DisableMFA checks mfa_enabled (coreGateExcluded).
//	Positive control: pkMFAUser (the only principal with mfa_enabled=true).
//
// mfa.recovery-codes.regenerate:
//
//	Same structure as mfa.disable. Positive control: pkMFAUser.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext5StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT5 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext5Op(spec.name) {
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
					// No curated RBAC-boundary variations: none of the 3 ops have an
					// RBAC permission gate. The only authorization boundary is the
					// account-state check (mfa_enabled / pending enrollment), which is
					// exercised by the named principals (pkMFAUser, pkMFAEnrollee).
				}
			}
		})
	}
	t.Logf("V5EXT5 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT5 cases: a positive control (pkMFAEnrollee for mfa.activate, pkMFAUser for mfa.disable and mfa.recovery-codes.regenerate) was not allowed — fix the op binding or the V5EXT5 fixture seed", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT5 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 3 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// TestMFARouteGatesPresent verifies that all four MFA self-service routes in
// server/http/router.go carry the BlockWhenImpersonating middleware anchor.
//
// BlockWhenImpersonating is the ONLY authorization gate for these routes:
//   - mfa.enroll: also blocked by authEncryptor=nil in test mode (BeginMFAEnrollment).
//   - mfa.activate: additionally gated by pending enrollment state (not an RBAC gate).
//   - mfa.disable: additionally gated by mfa_enabled state (not an RBAC gate).
//   - mfa.recovery-codes.regenerate: same as mfa.disable.
//
// Without BlockWhenImpersonating, an impersonating admin could enroll or disable
// MFA on behalf of a victim — a security property independent of the oracle.
//
// Red/green proof:
//   - RED: remove any BlockWhenImpersonating anchor from router.go → test fails.
//   - GREEN: tree as committed → all 4 anchors found exactly once → test passes.
//
// What it does NOT verify: it is a source-text match on router.go, so a
// reformat, an alias rename (customMiddleware) or a handler rename breaks it
// without any behaviour change. It does not prove that the routes sit inside
// the authenticated route group, the middleware order, or that
// BlockWhenImpersonating refuses at runtime; no request is sent.
func TestMFARouteGatesPresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	s := string(src)
	anchors := []string{
		`r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", authHandler.EnrollMFA)`,
		`r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/activate", authHandler.ActivateMFA)`,
		`r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/disable", authHandler.DisableMFA)`,
		`r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/recovery-codes/regenerate", authHandler.RegenerateRecoveryCodes)`,
	}
	for _, anchor := range anchors {
		if n := strings.Count(s, anchor); n != 1 {
			t.Errorf("MFA BlockWhenImpersonating anchor found %d times (want 1): %q", n, anchor)
		}
	}
}
