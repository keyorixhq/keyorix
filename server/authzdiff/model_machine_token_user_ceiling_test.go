package authzdiff

import (
	"slices"
	"testing"
)

// Table-driven proof of the #4332 (fuzz-corpus#91) rule as the reference model
// now encodes it: a USER caller issuing a machine token for an existing machine
// must hold every permission that machine holds, at the scope it holds it — the
// same ceiling a machine caller has followed since #3993. The target machine
// (fx.proj(B).machineID) holds project_auditor = {secrets.read, users.read,
// audit.read} at project B, so the custom user covers it only by holding all
// three at a scope that reaches B, on top of the op's own roles.assign gate.
//
// Each row asserts BOTH the model's decision AND core's (the product) and that
// the harness classifies them as agreeing (not "unexplained"): the model is
// right only if it predicts what core actually does. The first branch of the
// #4332 fix (false positive f1be67fcde954c04) was the model allowing where core
// denies; a wrong model that over-denies would be caught here just as surely by
// the core==model assertion.
func TestModel_MachineTokenIssue_UserCeiling(t *testing.T) {
	specs := withDerived(t, ops())
	i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == "machine.token.issue" })
	if i < 0 {
		t.Fatal("machine.token.issue op not found")
	}
	spec := specs[i]

	// maskFor turns permission names into the custom-role bit mask the variation
	// installs (bit j = customPermUniverse[j]).
	maskFor := func(names ...string) uint16 {
		var m uint16
		for _, n := range names {
			j := slices.Index(customPermUniverse, n)
			if j < 0 {
				t.Fatalf("permission %q not in customPermUniverse", n)
			}
			m |= 1 << j
		}
		return m
	}

	// project_auditor's bundle plus the op's roles.assign gate: the minimal set a
	// user needs to both pass the gate and cover target machine B.
	coverAll := maskFor("secrets.read", "users.read", "audit.read", "roles.assign")

	cases := []struct {
		name  string
		mask  uint16
		route string
		scope string
		want  Outcome
		why   string
	}{
		{"covers-all-at-global", coverAll, "user", "global", Allowed,
			"holds roles.assign and every project_auditor perm; a global grant reaches project B"},
		{"covers-all-at-project-B", coverAll, "user", "B", Allowed,
			"same, held directly at the target's own project"},
		{"all-perms-at-global", allPerms, "user", "global", Allowed,
			"a superset of the target's perms covers it"},
		{"lacks-users.read", maskFor("secrets.read", "audit.read", "roles.assign"), "user", "global", Denied,
			"target holds users.read (project_auditor); caller does not — ceiling refuses"},
		{"lacks-audit.read", maskFor("secrets.read", "users.read", "roles.assign"), "user", "global", Denied,
			"target holds audit.read (project_auditor); caller does not — ceiling refuses"},
		{"lacks-roles.assign-gate", maskFor("secrets.read", "users.read", "audit.read"), "user", "global", Denied,
			"covers the target but lacks the op's own roles.assign@project gate"},
		{"covers-but-at-sibling-project-A", coverAll, "user", "A", Denied,
			"grant is scoped to project A; it reaches neither the roles.assign gate nor the ceiling at project B — AuthorizePrincipal is not satisfied at B for a grant held only at A"},
		{"crasher-f1be67-secrets.read+delete+assign-via-group", maskFor("secrets.read", "secrets.delete", "roles.assign"), "group", "global", Denied,
			"the exact fuzz crasher: lacks users.read and audit.read that project_auditor holds"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k := caseKey{
				Op:        spec.name,
				Principal: pkCustom,
				Target:    tB.String(),
				Arg:       0,
				variation: variation{Mask: tc.mask & allPerms, Route: tc.route, Scope: tc.scope},
			}
			r := runCase(t, spec, k, tB)
			if r.Model != tc.want {
				t.Errorf("model = %s, want %s (%s)", r.Model, tc.want, tc.why)
			}
			core := r.Legs[layerCore]
			if core == nil || core.NA != "" {
				t.Fatalf("core leg absent/NA (%v): the product oracle must participate", core)
			}
			if core.Outcome != tc.want {
				t.Errorf("core = %s (%s), want %s (%s)", core.Outcome, core.Detail, tc.want, tc.why)
			}
			if r.Bucket == "unexplained" {
				t.Errorf("model and the enforcing layers disagree: %s", r.line())
			}
		})
	}
}
