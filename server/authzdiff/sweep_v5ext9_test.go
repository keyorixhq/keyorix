package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext9StrictSweep is a deterministic, env-free strict check over the
// V5EXT9 group of operations (see isV5ext9Op for the full list).
//
// V5EXT9 ops:
//
//	impersonation.end: impersonatingSession+humanOnly. No RBAC gate on route.
//	  core_refusal:"none"; core excluded from Oracle.
//	  Positive control: pkImpersonating (controlAs). Every named principal uses
//	  a regular (non-impersonating) session and gets HTTP 400 from the handler;
//	  Denied && PreconditionFailed has no classifier class → not a disagreement.
//	  Curated: none.
//
//	webauthn.deleteCredential: mfaRequired. BlockWhenImpersonating only on route.
//	  core_refusal:"none"; core excluded from Oracle.
//	  Positive control: pkMFAUser (controlAs; pkGlobalAdmin has no MFA → 400).
//	  Curated: none (every named non-pkMFAUser principal gets 400 → PreconditionFailed;
//	  Denied && PreconditionFailed and PreconditionFailed && PreconditionFailed have
//	  no classifier class → not disagreements).
//
//	mfaReset.request: globalAdminRole+humanOnly+mfaRequired. Route gate users.write@global
//	  is weaker than core's requireMFAResetActor check (HARDENING-V5EXT9-1 —
//	  same pattern as HARDENING-V5EXT8-1 for mfaReset.cancel).
//	  core_refusal:"none"; core excluded from Oracle.
//	  Positive control: pkMFAResetActor (global admin + TOTP; controlAs).
//	  Curated: custom user with users.write@global but no admin role → route passes,
//	  core returns ErrMFAResetAdminRequired → REST=Denied, model=Denied. MATCH.
//
//	mfaReset.approve: same as mfaReset.request.
//	  Positive control: pkMFAResetActor (the approver; requester is u-v9-mfa-admin-b
//	  — dual-control is always satisfied for pkMFAResetActor by fixture construction).
//	  Curated: same custom-user variation as mfaReset.request.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext9StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT9 strict sweep drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext9Op(spec.name) {
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
					for _, cv := range curatedV5ext9Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT9 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT9 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT9 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 4 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext9Variations returns gate-boundary cases for V5EXT9 ops.
//
//   - impersonation.end: no curated variations. The named sweep already shows
//     that every non-impersonating token gets HTTP 400 → PreconditionFailed, which
//     the classifier treats as a match (Denied/PreconditionFailed have no class).
//   - webauthn.deleteCredential: no curated variations. requireReauth fails for all
//     non-pkMFAUser principals; PreconditionFailed && PreconditionFailed = match.
//   - mfaReset.request: custom user with users.write@global but no admin role.
//     Route passes, core returns ErrMFAResetAdminRequired → 403 → Denied, model=Denied.
//   - mfaReset.approve: same custom variation.
func curatedV5ext9Variations(spec opSpec, _ tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	switch spec.name {
	case "mfaReset.request", "mfaReset.approve":
		// users.write@global but NOT an admin role: route gate passes, core denies
		// (ErrMFAResetAdminRequired → 403 → Denied), model=Denied (no globalAdminRole).
		usersWrite := maskOf([]string{"users.write"})
		return []pv{
			{pkCustom, variation{Mask: usersWrite, Route: "user", Scope: "global"}},
		}
	}
	return nil
}

// isV5ext9Op reports whether name is covered by TestV5ext9StrictSweep.
func isV5ext9Op(name string) bool {
	switch name {
	case "impersonation.end", "webauthn.deleteCredential", "mfaReset.request", "mfaReset.approve":
		return true
	}
	return false
}

// TestEndImpersonationRouterGatePresent asserts that the POST /auth/end-impersonation
// route registration in server/http/router.go exactly matches what this sweep tests
// (no RBAC gate — the check is in the handler and core).
//
// What this does NOT verify: that the route is under the authenticated middleware
// group (the router groups are not easily assertable by text search).
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

// TestDeleteWebAuthnCredentialRouterGatePresent asserts that the DELETE route
// for WebAuthn credentials exactly matches what this sweep tests.
//
// What this does NOT verify: HARDENING — BlockWhenImpersonating is weaker than a
// full RBAC gate; documented in ops_v5ext9_test.go.
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

// TestMFAResetRequestRouterGatePresent asserts that the POST /mfa-reset-requests
// route registration in server/http/router.go exactly matches what this sweep tests.
//
// What this does NOT verify: HARDENING-V5EXT9-1 (users.write gate is weaker than
// core's requireMFAResetActor, which requires globalAdminRole + TOTP).
func TestMFAResetRequestRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests", handlers.RequestMFAReset)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("mfaReset.request router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

// TestMFAResetApproveRouterGatePresent asserts that the POST /mfa-reset-requests/{id}/approve
// route registration in server/http/router.go exactly matches what this sweep tests.
//
// What this does NOT verify: HARDENING-V5EXT9-1 (same as mfaReset.request).
func TestMFAResetApproveRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests/{id}/approve", handlers.ApproveMFAReset)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("mfaReset.approve router gate anchor found %d times (want 1): %q", n, anchor)
	}
}
