package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext3StrictSweep is a deterministic, env-free strict check over the
// V5EXT3 bindings (ops_v5ext3_test.go): bulk.delete, bulk.rename,
// bulk.suspend, and resume.all.
//
// All four ops have no gRPC leg (matrix.json grpc=null for each). The oracle
// signal is REST and core vs the model. Core enforces a per-item authorization
// check (via EnforceSecretOwnerPermission / EnforceSecretWritePermission with
// an RBAC fallback); machine actors return errNotAuthzLayer so the core leg is
// excluded from both oracles for machines.
//
// Curated variations cover the router gate boundary: a custom principal with
// / without the required permission, via group, and via a machine token.
// Resume.all requires pp.suspendedSecretID (pre-suspended in the V5EXT3 seed)
// for the positive-control admin to get n ≥ 1 from ResumeProjectSecrets.
//
// The sweep also runs secret.extend.expiring (bound in ops_phase5_test.go): it
// is the fifth project-wide secrets.write@project op whose route gate core
// decides itself (#4657), and no other always-on strict check covers it.
//
// Strict rule: zero uncalibrated cases and zero "unexplained" cases.
func TestV5ext3StrictSweep(t *testing.T) {
	if testing.Short() {
		t.Skip("V5EXT3 strict check drives real core+REST legs; skipped under -short")
	}
	tally := &sweepTally{disBuckets: map[string]int{}, gapBuckets: map[string]int{}}
	for _, spec := range withDerived(t, ops()) {
		if !isV5ext3SweptOp(spec.name) {
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
					for _, cv := range curatedV5ext3Variations(spec, tg) {
						run(cv.pk, cv.v)
					}
				}
			}
		})
	}
	t.Logf("V5EXT3 check: %d cases, %d with an O1/O2 class, %d uncalibrated", tally.n, tally.dis, tally.uncalibrated)
	t.Logf("partition of O1/O2 cases: %v", tally.disBuckets)
	t.Logf("partition of mapping-gap-only cases: %v", tally.gapBuckets)
	if tally.uncalibrated > 0 {
		t.Errorf("%d uncalibrated V5EXT3 cases: an admin positive control failed — fix the op binding", tally.uncalibrated)
	}
	if tally.disBuckets["unexplained"] > 0 || tally.gapBuckets["unexplained"] > 0 {
		t.Errorf("unexplained V5EXT3 cases present: a disagreement or mapping gap no known waiver absorbs")
	}
	if tally.n < 10 {
		t.Errorf("only %d cases ran — the curated case space did not run", tally.n)
	}
}

// isV5ext3SweptOp reports whether TestV5ext3StrictSweep runs name: the V5EXT3
// bindings plus secret.extend.expiring, which shares their route gate.
func isV5ext3SweptOp(name string) bool {
	return isV5ext3Op(name) || name == "secret.extend.expiring"
}

// curatedV5ext3Variations: gate-boundary cases for a V5EXT3 op at target t.
//
// All four ops use a project-scoped permission gate:
//   - bulk.delete: secrets.delete @ project
//   - bulk.rename, bulk.suspend, resume.all: secrets.write @ project
//
// Curated variations: custom holds/lacks the perm, custom via-group, machine holds/lacks.
//
// Two per-op constraints shape the cases here:
//
//  1. bulk.delete: BulkDeleteSecrets calls GetSecretWithPermissionCheck before
//     DeleteSecretWithPermissionCheck. GetSecretWithPermissionCheck requires
//     secrets.read (or ownership/ACL-read). The curated positive case therefore
//     grants BOTH secrets.read and secrets.delete; granting only secrets.delete
//     would cause the per-item GET check to fail, making core and REST over-deny
//     what the model (router-gate-only) says "allowed". The "lacks" case grants
//     everything except secrets.delete (secrets.read included) so the GET passes
//     but the DELETE RBAC check fails, correctly matching model=denied.
//
//  2. bulk.rename, bulk.suspend, resume.all: BulkRenameSecrets, SuspendProjectSecrets,
//     and ResumeProjectSecrets refuse a machine actor with ErrPermissionDenied and
//     REST answers 403 (#4514); the model marks them human-only, so machine+holds
//     is denied everywhere and is swept. The machine+lacks variation (machine
//     without secrets.write → router 403) exercises the router gate as before.
//     For bulk.delete, the machine+holds variation is kept: BulkDeleteSecrets treats
//     actorID=0 as the CLI caller (skipping permission checks), so a machine that passes
//     the router gate CAN delete the secret — restOK returns true, core n/a, model
//     allowed → all agree.
func curatedV5ext3Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}

	perm := "secrets.write"
	if spec.name == "bulk.delete" {
		perm = "secrets.delete"
	}
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	// gatePerm: the single-perm bit the router gate requires (secrets.delete or
	// secrets.write). Used to build the "lacks" variation (allPerms minus gatePerm).
	gatePerm := maskOf([]string{perm})

	// For bulk.delete: positive case needs BOTH secrets.read and secrets.delete
	// (GetSecretWithPermissionCheck requires secrets.read; see note above).
	// For other ops: positive case needs only secrets.write.
	havePerms := []string{perm}
	if spec.name == "bulk.delete" {
		havePerms = []string{"secrets.delete", "secrets.read"}
	}
	have := maskOf(havePerms)

	cvs := []pv{
		{pkCustom, variation{Mask: have, Route: "user", Scope: here}},                     // holds perm(s)@here → allowed
		{pkCustom, variation{Mask: allPerms &^ gatePerm, Route: "user", Scope: here}},     // lacks gate perm → denied
		{pkCustom, variation{Mask: have, Route: "user", Scope: other}},                    // holds only at other → denied here
		{pkCustom, variation{Mask: have, Route: "group", Scope: here}},                    // via live group → allowed
		{pkMachine, variation{Mask: allPerms &^ gatePerm, Route: "machine", Scope: here}}, // machine lacks perm → denied (router 403)
	}
	// Machine+holds: bulk.delete takes the CLI bypass (allowed everywhere); the
	// other three refuse a machine actor (403, human-only in the model, #4514).
	cvs = append(cvs, pv{pkMachine, variation{Mask: have, Route: "machine", Scope: here}})
	return cvs
}

// TestBulkSecretRouterGatesPresent verifies the four V5EXT3 router gates are
// registered in server/http/router.go exactly as the authzdiff harness expects.
//
// Differential plants cannot detect gate removal for these ops: the per-item
// RBAC fallback (#r124) in BulkDeleteSecrets, BulkRenameSecrets,
// SuspendProjectSecretsWithOptions, and ResumeProjectSecrets enforces the same
// permission as the router gate for every user-actor principal. When the gate is
// removed, unauthorized user actors still get 200+empty-result (the per-item
// check rejects their items), which the harness classifies as denied — identical
// to the 403 they receive when the gate is present. No case crosses the
// allowed/denied boundary, so the differential harness sees nothing new.
//
// The router gates are still required as defense-in-depth (early rejection,
// correct HTTP status 403 vs. misleading 200+empty). This test asserts their
// presence structurally: it fails immediately when any of the four gate
// registrations are absent, edited, or moved.
//
// Red/green proof (all four anchors verified against the live router):
//   - RED: remove any anchor from router.go → this test fails.
//   - GREEN: tree as committed → this test passes (anchors exist exactly once).
func TestBulkSecretRouterGatesPresent(t *testing.T) {
	src, err := os.ReadFile("../../server/http/router.go")
	if err != nil {
		t.Fatalf("cannot read server/http/router.go: %v", err)
	}
	for _, anchor := range []string{
		`r.With(customMiddleware.RequireScopedPermission(permSecretsDelete, projectScope)).Post("/projects/{id}/secrets/bulk-delete", secretHandler.BulkDeleteSecrets)`,
		`r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/bulk-rename", secretHandler.BulkRenameSecrets)`,
		`r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/suspend-all", secretHandler.SuspendProjectSecrets)`,
		`r.With(customMiddleware.RequireScopedPermission(permSecretsWrite, projectScope)).Post("/projects/{id}/secrets/resume-all", secretHandler.ResumeProjectSecrets)`,
	} {
		if n := strings.Count(string(src), anchor); n != 1 {
			t.Errorf("bulk-secret router gate anchor found %d times (want 1): %q", n, anchor)
		}
	}
}
