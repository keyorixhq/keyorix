package authzdiff

import "testing"

// TestV5ext6bStrictSweep is a deterministic, env-free strict check over the
// V5EXT6B binding (ops_v5ext6b_test.go): mfa.enroll (BeginMFAEnrollment).
//
// mfa.enroll:
//
//	No RBAC gate. Core: BeginMFAEnrollment checks the auth encryptor (wired since
//	V5EXT6B) and user.MFAEnabled (coreGateExcluded=true).
//	Positive control: pkGlobalAdmin (no MFA enabled, no pending enrolment).
//	Model: noMFARequired + accountState — only pkMFAUser (mfa_enabled=true) is
//	refused (PreconditionFailed, REST 400 "MFA is already enabled"); a restricted
//	PAT and a suspended actor are Denied.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext6bStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT6B strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext6bOp(spec.name) {
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
					// No curated RBAC-boundary variations: no RBAC permission gate. The
					// only authorization boundary is mfa_enabled (noMFARequired),
					// exercised by the named principals (pkMFAUser).
				}
			}
		})
	}
	t.Logf("V5EXT6B check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT6B cases: the pkGlobalAdmin positive control was not allowed — fix the op binding or the enc fixture", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT6B cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 1 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}
