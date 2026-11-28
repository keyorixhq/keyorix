package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestImpersonationStrictSweep is a deterministic, env-free strict check over the
// Stage-3 bindings (ops_impersonation_test.go): impersonation.start,
// impersonation.end, webauthn.deleteCredential.
//
//	impersonation.start: users.impersonate@global (admin-bypass only), humanOnly.
//	  Route gate is load-bearing (core_refusal:"none"; core excluded from Oracle).
//	  Positive control: pkGlobalAdmin.
//
//	impersonation.end: impersonatingSession + humanOnly + accountState. No RBAC
//	  gate on the route; the session-state check is in core. Positive control:
//	  pkImpersonating (controlAs). Every named human with a regular session gets
//	  HTTP 400 "Not an impersonation session" → PreconditionFailed; a PAT bearer is
//	  refused 403 (session-only endpoint), matched by the model's restricted-PAT
//	  write-refusal rule (POST /auth/end-impersonation is in that table); a machine
//	  is refused 403 (humanOnly).
//
//	webauthn.deleteCredential: mfaRequired + accountState. BlockWhenImpersonating
//	  only on the route. Positive control: pkMFAUser (controlAs; it owns the
//	  credential fixture and has TOTP). Every other named principal fails
//	  requireReauth → HTTP 400 → PreconditionFailed; a PAT is refused (the route is
//	  in the restricted-PAT write-refusal table).
//
// What this oracle does NOT verify: see the per-op doc comments in
// ops_impersonation_test.go (session-auth path, cookie swap, passkey assertion,
// admin-authority re-check, etc.).
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestImpersonationStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("impersonation strict sweep drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isImpersonationOp(spec.name) {
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
					// No curated RBAC-boundary variations: impersonation.start is
					// admin-bypass-only (no partial-permission boundary among the named
					// set); impersonation.end and webauthn.deleteCredential have no RBAC
					// gate (the boundary is session-state / MFA-state, exercised by the
					// named principals and the controlAs positive control).
				}
			}
		})
	}
	t.Logf("impersonation check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated impersonation cases: a positive control (pkGlobalAdmin for impersonation.start, pkImpersonating for impersonation.end, pkMFAUser for webauthn.deleteCredential) was not allowed — fix the op binding or the fixture seed", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained impersonation cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 3 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// TestImpersonateStartRouterGatePresent asserts the impersonate POST route gate in
// server/http/router.go exactly matches what this sweep tests.
// What this does NOT verify: that the gate is applied to the correct HTTP method.
func TestImpersonateStartRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := "r.With(customMiddleware.RequirePermission(\"users.impersonate\")).\n\t\t\tPost(\"/admin/impersonate\", impersonationHandler.Start)"
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("impersonation.start router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

// TestEndImpersonationRouterGatePresent asserts the end-impersonation route (no
// RBAC gate — the check is in the handler and core) exactly matches what this
// sweep tests.
// What this does NOT verify: that the route is under the authenticated group.
func TestEndImpersonationRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.Post("/auth/end-impersonation", impersonationHandler.End)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("impersonation.end router anchor found %d times (want 1): %q", n, anchor)
	}
}

// TestDeleteWebAuthnCredentialRouterGatePresent asserts the DELETE route for
// WebAuthn credentials exactly matches what this sweep tests.
// What this does NOT verify: HARDENING — BlockWhenImpersonating is weaker than a
// full RBAC gate (documented in ops_impersonation_test.go).
func TestDeleteWebAuthnCredentialRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.BlockWhenImpersonating).Delete("/auth/webauthn/credentials/{id}", authHandler.DeleteWebAuthnCredential)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("webauthn.deleteCredential router anchor found %d times (want 1): %q", n, anchor)
	}
}
