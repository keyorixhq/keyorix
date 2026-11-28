package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestMFAResetStrictSweep is a deterministic, env-free strict check over the
// Stage-4 bindings (ops_mfareset_test.go): mfaReset.cancel, mfaReset.request,
// mfaReset.approve.
//
//	mfaReset.cancel: globalAdminRole + humanOnly. Route gate users.write@global is
//	  weaker than core's isGlobalAdminRoleName (HARDENING-V5EXT8-1). Positive
//	  control: pkGlobalAdmin. Curated: pkCustom with users.write@global but no admin
//	  role → route passes, core refuses (ErrMFAResetAdminRequired → 403 Denied),
//	  model Denied → MATCH (the gap is observable, not a silent pass).
//
//	mfaReset.request / mfaReset.approve: globalAdminRole + humanOnly + mfaRequired.
//	  Route gate users.write@global is weaker than core's requireMFAResetActor
//	  (admin role + a second factor). Positive control: pkMFAResetActor (global admin
//	  + TOTP). An admin without a second factor (pkGlobalAdmin) is refused 403 by core
//	  — a hard denial, matched by the model's mfaRequired (no accountState). Curated:
//	  pkCustom with users.write@global, no admin role → 403 Denied, model Denied.
//
// What this oracle does NOT verify: see the per-op doc comments in
// ops_mfareset_test.go (dual-control attack surface, anti-replay, status guards,
// and the HARDENING route-vs-core plant that would need a third TOTP fixture user).
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestMFAResetStrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("MFA-reset strict sweep drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isMFAResetOp(spec.name) {
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
					for _, cv := range curatedMFAResetVariations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("MFA-reset check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated MFA-reset cases: a positive control (pkGlobalAdmin for mfaReset.cancel, pkMFAResetActor for request/approve) was not allowed — fix the op binding or the fixture seed", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained MFA-reset cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 3 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedMFAResetVariations returns the gate-boundary case for the mfaReset ops:
// a custom user holding users.write@global but no admin role. It passes the route
// gate (users.write@global) and is refused by core (ErrMFAResetAdminRequired →
// 403 Denied) where the model agrees (no globalAdminRole → Denied). This makes the
// route-vs-core HARDENING gap an observable Denied, not a silently passing case.
func curatedMFAResetVariations(spec opSpec, _ tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	if isMFAResetOp(spec.name) {
		usersWrite := maskOf([]string{"users.write"})
		return []pv{
			{pkCustom, variation{Mask: usersWrite, Route: "user", Scope: "global"}},
		}
	}
	return nil
}

// TestMFAResetCancelRouterGatePresent / Request / Approve assert the mfa-reset route
// gate registrations in server/http/router.go exactly match what this sweep tests.
// What they do NOT verify: HARDENING-V5EXT8/9-1 (the route gate users.write@global
// is weaker than core's admin-role + second-factor check).
func TestMFAResetCancelRouterGatePresent(t *testing.T) {
	src := readRouterSrc(t)
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests/{id}/cancel", handlers.CancelMFAReset)`
	if n := strings.Count(src, anchor); n != 1 {
		t.Errorf("mfaReset.cancel router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

func TestMFAResetRequestRouterGatePresent(t *testing.T) {
	src := readRouterSrc(t)
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests", handlers.RequestMFAReset)`
	if n := strings.Count(src, anchor); n != 1 {
		t.Errorf("mfaReset.request router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

func TestMFAResetApproveRouterGatePresent(t *testing.T) {
	src := readRouterSrc(t)
	anchor := `r.With(customMiddleware.RequirePermission(permUsersWrite)).Post("/mfa-reset-requests/{id}/approve", handlers.ApproveMFAReset)`
	if n := strings.Count(src, anchor); n != 1 {
		t.Errorf("mfaReset.approve router gate anchor found %d times (want 1): %q", n, anchor)
	}
}

func readRouterSrc(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	return string(src)
}
