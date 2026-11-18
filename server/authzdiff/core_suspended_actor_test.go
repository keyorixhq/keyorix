package authzdiff

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/keyorixhq/keyorix/internal/core"
)

// suspendedUncheckableOps are the core-enforced ops for which neither suspended
// principal below has a case the active principal would be allowed (so there is
// nothing to refuse), each with the reason. A new op lands here only with a
// reason; an op missing from it with no checked case fails the guard.
// Every other core-enforced op has a checked case.
var suspendedUncheckableOps = map[string]string{}

// TestCoreRefusesSuspendedActor: for every bound op whose core method is an
// authorization layer, a suspended human actor is refused by core itself
// wherever the same principal would be allowed once active — the transports
// already refuse it at authentication (#4159, the former waiver known-02;
// the value reads secret.value.byid/byref too since #4336). Two suspended
// principals, so that the op families one of them cannot reach are still
// checked:
//   - the harness's pkSuspended (project_admin@A, suspended after login), run
//     through runCase on all three layers;
//   - the fixture admin (global admin, project_admin@A and @B, owner of every
//     fixture secret and share), suspended in its own core leg: it is the
//     principal the model allows on global role/user ops and on the owner-only
//     share ops (secret.share, share.update), where project_admin@A is refused
//     anyway and so checks nothing.
//
// A case is CHECKED when the active principal would be allowed (ModelIfActive)
// and the core leg took part (calibrated, not n/a). Every op must have at least
// one checked case, or be in suspendedUncheckableOps with a reason: a guard that
// skips every case of an op vouches for nothing (REVIEW-4336-DEEP-1 F1).
//
// Not covered here: other non-active states (deprovisioned, deactivated) — they
// share requireActorActive's single rule (AccountLoginBlocked, IsActive), which
// internal/core tests directly; and ops whose core method takes no actor or is
// transport-enforced (coreEnforced false): there core is not an authorization
// layer, and the transports' refusal is the only one.
func TestCoreRefusesSuspendedActor(t *testing.T) {
	for _, spec := range withDerived(t, ops()) {
		if !spec.coreEnforced {
			continue
		}
		t.Run(spec.name, func(t *testing.T) {
			t.Parallel()
			checked := 0
			for _, tg := range spec.targets {
				for _, arg := range argsFor(spec) {
					if spec.invalidArg != nil && spec.invalidArg(tg, arg) {
						continue
					}
					r := runCase(t, spec, caseKey{Op: spec.name, Principal: pkSuspended, Target: tg.String(), Arg: arg, variation: defaultVariation}, tg)
					if core := r.Legs[layerCore]; r.ModelIfActive == Allowed && core != nil && core.NA == "" {
						checked++
						if core.Outcome == Allowed {
							t.Errorf("core allowed a suspended actor that the transports refuse: %s", r.line())
						}
					}
					if out, ok := suspendedAdminCoreCase(t, spec, tg, arg); ok {
						checked++
						if out.Outcome == Allowed {
							t.Errorf("core allowed the suspended fixture admin: op=%s target=%s arg=%d core=%s(%s)", spec.name, tg, arg, out.Outcome, out.Detail)
						}
					}
				}
			}
			reason, listed := suspendedUncheckableOps[spec.name]
			switch {
			case checked == 0 && !listed:
				t.Errorf("op %s: no checked case, guard is vacuous for it (add a suspended principal the model allows, or list it in suspendedUncheckableOps with a reason)", spec.name)
			case checked > 0 && listed:
				t.Errorf("op %s: listed in suspendedUncheckableOps (%s) but has %d checked case(s); remove the entry", spec.name, reason, checked)
			}
		})
	}
}

// suspendedAdminCoreCase runs spec's core leg as the fixture admin with the
// admin's account suspended in that leg's private database (the template, and so
// every other case, keeps it active). ok is false when the case checks nothing:
// no core leg, an owner/ACL fixture arg outside the model's domain, an
// uncalibrated admin control, a model that would refuse the admin anyway, or a
// core method that is not an authorization layer for this principal.
func suspendedAdminCoreCase(t *testing.T, spec opSpec, tg tgt, arg byte) (out result, ok bool) {
	t.Helper()
	if spec.core == nil || (spec.secretArgs && arg != 0) {
		return result{}, false
	}
	if c := control(t, spec, layerCore, tg, arg); c.NA != "" || c.Outcome != Allowed {
		return result{}, false
	}
	_, fx := template(t)
	admin := *fx.principals[pkGlobalAdmin]
	lg := newLeg(t, layerCore)
	defer lg.close()
	lg.applyVariation(t, defaultVariation)
	if !(model{lg.db}).allowed(&admin, spec.req(lg.fx, tg, arg)) || patRefusesUngatedWrite(t, lg.fx, spec, &admin) {
		return result{}, false
	}
	// Direct write: SuspendUser's last-admin guard refuses suspending the only
	// global admin, and this world exists for one core call only.
	if e := lg.db.Exec("UPDATE users SET is_active = ?, account_state = ? WHERE id = ?", false, core.AccountSuspended, admin.userID).Error; e != nil {
		t.Fatalf("suspend the fixture admin in its leg: %v", e)
	}
	err := spec.core(actorCtx(context.Background(), &admin), lg, &admin, tg, arg)
	switch {
	case errors.Is(err, errNotAuthzLayer):
		return result{}, false
	case errors.Is(err, errItemRefused):
		return result{Denied, "item-refused"}, true
	}
	r := coreOutcome(err)
	if r.Outcome == Other {
		r.Detail = fmt.Sprintf("%s: %v", r.Detail, err)
	}
	return r, true
}
