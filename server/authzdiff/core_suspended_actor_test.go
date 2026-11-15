package authzdiff

import (
	"testing"
)

// suspendedReadPathOps are the ops whose core leg is still allowed to answer a
// suspended actor: value reads on the hot read path (GetSecretValue*), which this
// session may not change (OPT-READPATH-2 owns read-path lookups). They are the
// only ops the narrowed waiver known-02 still matches (#4159); explain names the
// same two ops as literals (its enumeration test reads them from its source).
var suspendedReadPathOps = map[string]bool{"secret.value.byid": true, "secret.value.byref": true}

// TestCoreRefusesSuspendedActor: for every bound op whose core method is an
// authorization layer, a suspended human actor (the harness's project_admin@A,
// suspended after login) is refused by core itself wherever the same principal
// would be allowed once active — the transports already refuse it at
// authentication (#4159, waiver known-02). One case per op, target and arg, as
// the suspended principal with its own (project_admin@A) roles.
//
// Not covered here: other non-active states (deprovisioned, deactivated) — they
// share requireActorActive's single rule (AccountLoginBlocked, IsActive), which
// internal/core tests directly; and ops whose core method takes no actor or is
// transport-enforced (coreEnforced false): there core is not an authorization
// layer, and the transports' refusal is the only one.
func TestCoreRefusesSuspendedActor(t *testing.T) {
	for _, spec := range withDerived(t, ops()) {
		if !spec.coreEnforced || suspendedReadPathOps[spec.name] {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()
			for _, tg := range spec.targets {
				for _, arg := range argsFor(spec) {
					if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
						continue
					}
					r := runCase(t, spec, caseKey{Op: spec.name, Principal: pkSuspended, Target: tg.String(), Arg: arg, variation: defaultVariation}, tg)
					core := r.Legs[layerCore]
					if r.ModelIfActive != Allowed || core == nil || core.NA != "" {
						continue
					}
					if core.Outcome == Allowed {
						t.Errorf("core allowed a suspended actor that the transports refuse: %s", r.line())
					}
				}
			}
		})
	}
}
