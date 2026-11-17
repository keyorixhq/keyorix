package authzdiff

import (
	"slices"
	"testing"
)

// TestCeilingRefusalIsForbiddenOnREST: a principal that passes the REST route
// gate (roles.assign@A) but not core's own authority check (the granter
// ceiling for project_viewer, or the authority to reinstate the project's
// admin-tier role assignments) is refused by core with ErrPermissionDenied.
// REST must answer that refusal 403, not 500. Before AUTHZDIFF-TAILS-1 these
// four handlers fell through to their 500 default (former waiver known-07).
//
// Not covered here: the same refusal on routes outside these four ops; the
// full strict sweep finds those as unexplained cases now that the waiver is
// gone.
func TestCeilingRefusalIsForbiddenOnREST(t *testing.T) {
	names := []string{"userrole.assign", "accessrequest.approve", "invitation.create", "env.restore"}
	specs := withDerived(t, ops())
	for _, name := range names {
		i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == name })
		if i < 0 {
			t.Fatalf("op %s not defined", name)
		}
		spec := specs[i]
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			v := variation{Mask: maskOf([]string{"roles.assign"}), Route: "user", Scope: "A"}
			r := runCase(t, spec, caseKey{Op: name, Principal: pkCustom, Target: tA.String(), Arg: 0, variation: v}, tA)
			core, rest := r.Legs[layerCore], r.Legs[layerREST]
			if core == nil || core.NA != "" || core.Outcome != Denied || core.Detail != "ErrPermissionDenied" {
				t.Fatalf("precondition: core must refuse with ErrPermissionDenied: %s", r.line())
			}
			if rest == nil || rest.NA != "" || rest.Outcome != Denied || rest.Detail != "Forbidden" {
				t.Errorf("REST must answer core's ErrPermissionDenied with 403: %s", r.line())
			}
		})
	}
}
