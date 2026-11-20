package authzdiff

import (
	"os"
	"strings"
	"testing"
)

// TestV5ext7StrictSweep is a deterministic, env-free strict check over the
// V5EXT7 group of operations (see isV5ext7Op for the full list).
//
// V5EXT7 step 1 — phase5 share write ops (already bound; coreEnforced and
// strict sweep added here):
//
//	share.revoke: secrets.write + (owner OR secrets.manage). Core: requireActorActive
//	  + requireShareAuthority + revokerMayManageSecret. gRPC and REST.
//	  Positive control: pkAdmin (owner).
//	  Curated: custom user with both write+manage → allowed (non-owner manager
//	    path); custom with write-only → denied; machine → denied (p.machineID==0 gate).
//
//	share.update: secrets.write + (owner only). Core: requireActorActive +
//	  requireShareAuthority (owner-only, no alternative). gRPC and REST.
//	  Positive control: pkAdmin (owner).
//	  Curated: custom with secrets.write but not owner → denied.
//
//	share.self.remove: recipient-only (pkViewer and pkCustom). No RBAC gate.
//	  Core: RemoveSelfFromShare checks membership. REST only. Target: tA only.
//	  Positive control: pkViewer.
//
// V5EXT7 step 2 — phase5 env-copy ops (already bound; coreEnforced and
// strict sweep added here):
//
//	env.clone: secrets.write + secrets.read (both perms). Core: CloneEnvironment
//	  calls requireActorActive. REST only.
//	  Positive control: pkAdmin.
//	  Curated: write-only → denied; read-only → denied.
//
//	env.copy.secrets: same gates as env.clone. Core: CopyEnvironmentSecrets
//	  calls requireActorActive. REST only.
//	  Curated: same as env.clone.
//
// V5EXT7 step 3 — new schedule/classify ops:
//
//	secret.schedule.set: secrets.manage. Core: coreGateExcluded (SetSecretSchedule has
//	  no actorID — cannot check actor state; see HARDENING-2). REST only.
//	  Curated: manage → allowed; write-only → denied.
//
//	secret.schedule.delete: same as schedule.set.
//
//	secret.classify: secrets.write. Core: coreGateExcluded (ClassifySecret does not call
//	  requireActorActive; see HARDENING-1). REST only.
//	  Curated: write → allowed; read-only → denied.
//
// What this oracle does NOT verify:
//   - share.self.remove: RBAC gate (there is none; the only gate is recipient membership).
//   - env.clone / env.copy.secrets: dual-scope check (secrets.write at project +
//     secrets.read at env — the reference model uses project scope for both, so a
//     write-at-project / read-at-env split actor is not modelled here).
//   - secret.schedule.*: temporal effect (whether the schedule actually restricts access).
//     LogSecretScheduleSet / LogSecretScheduleDeleted audit events.
//   - secret.classify: the restricted-classification downgrade gate
//     (checkRestrictedSecretReadApproval) — fixture plainID is not classified "restricted".
//   - WebAuthn or MFA-step-up gate on any of these ops.
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
	if tally.n < 5 {
		t.Errorf("only %d cases ran — too few (bug in op list or target selection)", tally.n)
	}
}

// curatedV5ext7Variations returns gate-boundary cases for V5EXT7 ops.
//
//   - share.revoke: holds secrets.write+manage (non-owner manager path allowed);
//     holds write-only (non-owner, denied at core); machine holds both (denied:
//     model p.machineID==0 gate); via group with both (allowed).
//   - share.update: holds write but not owner (denied at core); via group not owner
//     (denied); machine holds write (denied — machine cannot be ownerUserID).
//   - share.self.remove: no curated RBAC cases (no RBAC gate; boundary is recipient).
//   - env.clone / env.copy.secrets: write-only → denied; read-only → denied.
func curatedV5ext7Variations(spec opSpec, t tgt) []struct {
	pk principalKind
	v  variation
} {
	type pv = struct {
		pk principalKind
		v  variation
	}
	here, other := "A", "B"
	if t == tB {
		here, other = "B", "A"
	}
	_ = other

	switch spec.name {
	case "share.revoke":
		// Gate: secrets.write required by route; core additionally requires owner
		// OR secrets.manage (revokerMayManageSecret). Machine: p.machineID!=0
		// means revokerMayManageSecret always returns false, so denied even with both.
		writeManage := maskOf([]string{"secrets.write", "secrets.manage"})
		writeOnly := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: writeManage, Route: "user", Scope: here}},     // non-owner + manage → allowed
			{pkCustom, variation{Mask: writeOnly, Route: "user", Scope: here}},       // non-owner, write only → denied
			{pkCustom, variation{Mask: writeManage, Route: "group", Scope: here}},    // via group + manage → allowed
			{pkMachine, variation{Mask: writeManage, Route: "machine", Scope: here}}, // machine → denied (p.machineID!=0)
		}
	case "share.update":
		// Gate: secrets.write required by route; core requires owner-only
		// (requireShareAuthority, no ownerOrPerm alternative). Any non-admin denied.
		write := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: write, Route: "user", Scope: here}},              // non-owner holds write → denied
			{pkCustom, variation{Mask: allPerms &^ write, Route: "user", Scope: here}},  // lacks write → denied
			{pkCustom, variation{Mask: write, Route: "group", Scope: here}},             // via group, non-owner → denied
			{pkMachine, variation{Mask: write, Route: "machine", Scope: here}},          // machine → denied (not owner)
		}
	case "share.self.remove":
		// No RBAC gate; authorization is entirely by recipient membership.
		return nil
	case "env.clone", "env.copy.secrets":
		// Route gates: secrets.write (project) AND secrets.read (env scope).
		// Reference model requires both. Test the two one-perm-short cases.
		writeRead := maskOf([]string{"secrets.write", "secrets.read"})
		writeOnly := maskOf([]string{"secrets.write"})
		readOnly := maskOf([]string{"secrets.read"})
		return []pv{
			{pkCustom, variation{Mask: writeRead, Route: "user", Scope: here}},  // both perms → allowed
			{pkCustom, variation{Mask: writeOnly, Route: "user", Scope: here}},  // write-only → denied (no read)
			{pkCustom, variation{Mask: readOnly, Route: "user", Scope: here}},   // read-only → denied (no write)
		}
	case "secret.schedule.set", "secret.schedule.delete":
		// Route gate: secrets.manage. Core: coreGateExcluded (no actorID). REST only.
		manage := maskOf([]string{"secrets.manage"})
		writeOnly := maskOf([]string{"secrets.write"})
		return []pv{
			{pkCustom, variation{Mask: manage, Route: "user", Scope: here}},     // manage → allowed
			{pkCustom, variation{Mask: writeOnly, Route: "user", Scope: here}},  // write-only (no manage) → denied
		}
	case "secret.classify":
		// Route gate: secrets.write (+ SecretActionClassify). Core: coreGateExcluded.
		// REST only. Standard write-only user allowed; read-only denied.
		write := maskOf([]string{"secrets.write"})
		readOnly := maskOf([]string{"secrets.read"})
		return []pv{
			{pkCustom, variation{Mask: write, Route: "user", Scope: here}},     // write → allowed
			{pkCustom, variation{Mask: readOnly, Route: "user", Scope: here}},  // read-only → denied
		}
	}
	return nil
}

// isV5ext7Op reports whether name is covered by TestV5ext7StrictSweep.
func isV5ext7Op(name string) bool {
	switch name {
	case
		// V5EXT7 step 1: phase5 share write ops
		"share.revoke", "share.update", "share.self.remove",
		// V5EXT7 step 2: phase5 env-copy ops
		"env.clone", "env.copy.secrets",
		// V5EXT7 step 3: new schedule/classify ops
		"secret.schedule.set", "secret.schedule.delete", "secret.classify":
		return true
	}
	return false
}

// TestSecretScheduleRouterGatesPresent asserts that the schedule PUT and DELETE
// route registrations in server/http/router.go exactly match what this sweep
// tests. Fails immediately if either gate registration is removed or changed,
// turning a silent coverage loss into a compile-time-equivalent build failure.
//
// What this does NOT verify: that the gate is applied to the correct HTTP method
// (a method-swap would need an integration test hitting the route).
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
// asserted by the core layer's own action-constant tests.
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
