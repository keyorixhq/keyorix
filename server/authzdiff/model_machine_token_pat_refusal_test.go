package authzdiff

import (
	"slices"
	"testing"
)

// Proof that the #4332 restricted-PAT refusal (HF3, fuzz-corpus#120) is
// exercised as the SOLE denier of a machine-token mint, on all three layers,
// and that the model's `if p.pat != nil { return false }` line in allowed() is
// load-bearing — the gap HF2 §6/§7 flagged: before pkPATFull, the only fixture
// PAT (pkPAT, restricted to secrets.read@A) already failed the roles.assign
// gate, so the refusal line could never change a verdict and had no planted
// defect.
//
// pkPATFull's owner is project_admin at A and B (so it fully covers either
// target machine's project_auditor role and holds roles.assign) and its PAT is
// confined to a permission allowlist that still Allows the roles.assign gate.
// So the gate and the privilege-ceiling check both pass, and only the
// restricted-PAT refusal denies it.
func TestModel_MachineTokenIssue_RestrictedPATRefused(t *testing.T) {
	specs := withDerived(t, ops())
	i := slices.IndexFunc(specs, func(s opSpec) bool { return s.name == "machine.token.issue" })
	if i < 0 {
		t.Fatal("machine.token.issue op not found")
	}
	spec := specs[i]

	for _, tg := range []tgt{tA, tB} {
		t.Run(tg.String(), func(t *testing.T) {
			k := caseKey{Op: spec.name, Principal: pkPATFull, Target: tg.String(), Arg: 0, variation: defaultVariation}
			r := runCase(t, spec, k, tg)

			// (1) model denies, and every live layer (core, REST, gRPC) denies:
			// the model's verdict matches the product on all three transports.
			if r.Model != Denied {
				t.Errorf("model = %s, want Denied (the restricted-PAT refusal)", r.Model)
			}
			for _, l := range []layer{layerCore, layerREST, layerGRPC} {
				lo := r.Legs[l]
				if lo == nil || lo.NA != "" {
					t.Fatalf("%s leg absent/NA (%v): the refusal must be exercised on this layer", l, lo)
				}
				if lo.Outcome != Denied {
					t.Errorf("%s = %s (%s), want Denied — the restricted-PAT refusal must deny on this layer", l, lo.Outcome, lo.Detail)
				}
			}
			if r.Bucket == "unexplained" {
				t.Errorf("model and the enforcing layers disagree: %s", r.line())
			}

			// (2) The refusal LINE is load-bearing: the same principal with its PAT
			// restriction cleared passes the gate AND the target-coverage ceiling, so
			// the model would ALLOW it — the only thing denying is `if p.pat != nil`.
			// (Red/green on the model line without editing the model: same world,
			// one field toggled.)
			lg := newLeg(t, layerCore)
			defer lg.close()
			lg.applyVariation(t, defaultVariation)
			m := model{lg.db}
			req := spec.req(lg.fx, tg, 0)
			p := lg.fx.principals[pkPATFull]
			if m.allowed(p, req) {
				t.Errorf("model.allowed(pkPATFull) = true, want false: the restricted-PAT refusal must deny")
			}
			noPAT := *p
			noPAT.pat = nil
			if !m.allowed(&noPAT, req) {
				t.Errorf("model.allowed(pkPATFull without its PAT) = false, want true: the gate and the " +
					"target-coverage ceiling must both pass, so ONLY the `if p.pat != nil` line denies — " +
					"otherwise this principal is not a clean isolation of the refusal")
			}
		})
	}
}
