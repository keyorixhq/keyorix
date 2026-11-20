package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext8StrictSweep is a deterministic, env-free strict check over the
// V5EXT8 group of operations (see isV5ext8Op for the full list).
//
// V5EXT8 ops:
//
//	impersonation.start: users.impersonate@global (admin-bypass only), humanOnly.
//	  Route gate is load-bearing (core_refusal:"none"; core excluded from Oracle).
//	  Positive control: pkGlobalAdmin.
//	  Curated: none (all named principals lacking users.impersonate@global are
//	    denied at the route; no curated variation adds meaningful boundary coverage
//	    beyond the route gate plant).
//
//	mfaReset.cancel: globalAdminRole+humanOnly. Route gate users.write@global is
//	  weaker than core's isGlobalAdminRoleName check (HARDENING-V5EXT8-1).
//	  core_refusal:"none"; core excluded from Oracle.
//	  Positive control: pkGlobalAdmin.
//	  Curated: custom user with users.write@global but no admin role → denied by
//	    core (ErrMFAResetAdminRequired → 403), model=Denied → agree. The plant
//	    removes the core check to prove the harness catches the gap.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext8StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT8 strict sweep drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext8Op(spec.name) {
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
					for _, cv := range curatedV5ext8Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT8 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT8 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT8 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 2 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext8Variations returns gate-boundary cases for V5EXT8 ops.
//
//   - impersonation.start: no curated variations. All named principals are either
//     denied at the route (no users.impersonate@global) or allowed (pkGlobalAdmin,
//     admin-bypass). The plant exercises the route gate boundary.
//   - mfaReset.cancel: custom with users.write@global but no admin role → route
//     allows (users.write@global), core denies (not admin-role name) → REST=Denied,
//     model=Denied (no globalAdminRole). Proves the harness's model rule is accurate.
func curatedV5ext8Variations(spec opSpec, _ tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	switch spec.name {
	case "mfaReset.cancel":
		// users.write@global but NOT an admin role: route gate passes, core denies.
		usersWrite := maskOf([]string{"users.write"})
		return []pv{
			{pkCustom, variation{Mask: usersWrite, Route: "user", Scope: "global"}},
		}
	}
	return nil
}

// isV5ext8Op reports whether name is covered by TestV5ext8StrictSweep.
func isV5ext8Op(name string) bool {
	switch name {
	case "impersonation.start", "mfaReset.cancel":
		return true
	}
	return false
}

// TestImpersonateStartRouterGatePresent asserts that the impersonate POST route
// registration in server/http/router.go exactly matches what this sweep tests.
// Fails immediately if the gate registration is removed or changed, turning a
// silent coverage loss into a compile-time-equivalent build failure.
//
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

// TestMFAResetCancelRouterGatePresent asserts that the mfaReset.cancel POST route
// registration in server/http/router.go exactly matches what this sweep tests.
//
// What this does NOT verify: HARDENING-V5EXT8-1 (route gate is weaker than core's
// isGlobalAdminRoleName check; documented in the V5EXT8 report as TODO-ISSUE).
func TestMFAResetCancelRouterGatePresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests/{id}/cancel", handlers.CancelMFAReset)`
	if n := strings.Count(string(src), anchor); n != 1 {
		t.Errorf("mfaReset.cancel router gate anchor found %d times (want 1): %q", n, anchor)
	}
}
