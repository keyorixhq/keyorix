package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// V5EXT ops: authorization-completeness extension over the risk-exception and
// break-glass families the earlier phases (V5/V8) deferred with a "model:"
// reason. As in every earlier phase, an op is bound ONLY where the three layers'
// allow/deny decision is a gate the reference model already expresses; the
// business state machines these endpoints also run (the risk-exception dual-
// control approval flow, the break-glass review lifecycle) are NOT authorization
// decisions the layers disagree on under the model and are left to each layer.
//
// Three ops are bound here; the rest of these families stay deferred for a
// STRUCTURAL reason recorded in the report: their core row is core_refusal:"typed"
// (so the core leg participates in both oracles) yet core does NOT re-check the
// router's scoped permission — it enforces only reviewer-independence / human-only
// / grant-exists controls. The core leg would then ALLOW a principal the router
// denies (and the model, which models the router permission, denies), a core-leg
// disagreement no waiver absorbs. riskexception.delete is the exception that CAN
// be bound: its core_refusal:"typed" comes from a REAL permission gate
// (creator-or-admin-tier) that the model's globalAdminRole requirement matches.
//
// Every binding is validated by its admin positive control (OUTCOMES.md
// precondition 2) and red-proved by a plant (plants_test.go); an uncalibrated
// binding fails a strict run, so none can silently empty the oracle.
func v5extOps() []opSpec {
	return append(v5extRiskExceptionOps(), v5extBreakGlassOps()...)
}

// ---- risk exceptions: approve + delete (create already bound in V8) ----
//
// POST /api/v1/risk-exceptions/{id}/approve records dual-control approval of a
// governed risk acceptance. The router gates it RequirePermission(permSystemWrite)
// at GLOBAL scope (router.go:1265). core.ApproveRiskException performs NO
// permission check (matrix core_refusal:"none"): it enforces only the business
// rules of dual control — a machine is refused (human-only), and the creator is
// refused (creator≠approver). The fixture's exception is created by a NON-probed
// user (u-risk-creator), so the creator rule never fires for a probed principal;
// and a machine never holds system.write@global in the fixtures (a machine role
// is always project-scoped), so the model denies every machine case and the
// human-only rule only ever refuses a case the model already denies. What varies
// by principal is therefore the router's system.write@global gate alone — a clean
// global-scope router-gate differential, the core leg excluded (ID-2), identical
// in shape to riskexception.create.
//
// DELETE /api/v1/risk-exceptions/{id} revokes an exception. The router gates it
// RequirePermission(permSystemWrite) at global scope too, but core.RevokeRiskException
// INDEPENDENTLY enforces creator-OR-admin-tier (matrix core_refusal:"typed", so the
// core leg DOES participate). With a non-probed creator, no probed principal is the
// creator, so the effective gate for every probed principal is "holds an admin role
// at global scope" — exactly the model's globalAdminRole requirement. A principal
// holding system.write@global but no admin role (a custom role) passes the router
// yet is refused by core, so REST denies and the core leg denies, matching the model:
// all three agree. The router's system.write gate is redundant with core here (an
// admin-tier principal necessarily holds system.write), so the red-proof plant
// targets core's creator-or-admin gate, not the router.
//
// Scope of these oracles: they check the gate that decides who may approve/revoke
// a risk exception. They do NOT model the SoD-live-violation re-validation on
// approval, the already-approved/already-revoked/expired state rules, or the audit
// side effects — those are per-layer business logic, equal by construction because
// the fresh-copy fixture is in the same state for every leg.
func v5extRiskExceptionOps() []opSpec {
	return []opSpec{
		{
			name: "riskexception.delete", row: "RevokeRiskException", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				// creator-OR-admin-tier; the fixture's creator is non-probed, so for
				// every probed principal the gate is an admin role at global scope.
				return requirement{globalAdminRole: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.RevokeRiskException(ctx, p.userID, lg.fx.riskExceptionID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodDelete, fmt.Sprintf("/api/v1/risk-exceptions/%d", fx.riskExceptionID), nil}
			},
		},
	}
}

// ---- break-glass: revoke (activate already bound in V5) ----
//
// POST /api/v1/projects/{id}/break-glass/{activationId}/revoke ends an active
// activation early. Unlike ActivateBreakGlass (self-service: NO router gate, the
// whole decision is core's IsProjectMember), revoke is gated roles.assign@project
// at BOTH transports — the REST router (RequireScopedPermission(permRolesAssign,
// projectScope), router.go:590) and the gRPC interceptor (authorizeScoped
// "roles.assign", break_glass_service.go). core.RevokeBreakGlass performs NO
// permission check (since #4546 it refuses an inactive acting account, so its
// matrix row is core_refusal:"typed", and coreGateExcluded keeps the core leg out
// of the gate oracles): it validates the activation
// exists, is not already revoked, and runs the last-project-admin guard — none of
// which varies by probed principal on a freshly-cloned active activation whose
// emergency role (project_developer, held by a non-probed member) is not an admin
// role. So this is a clean roles.assign@project gate differential across REST, gRPC
// and the model, the core leg excluded (ID-2). The red-proof plant removes the REST
// router gate, leaving the gRPC gate, so REST over-allows what gRPC and the model
// deny.
//
// Scope of this oracle: it checks the roles.assign@project gate that decides who
// may revoke an activation. It does NOT model the activation state machine, the
// last-admin guard, or the independence controls on the SEPARATE /review endpoint
// (which core_refusal:"typed" and which core does not re-gate on roles.assign — see
// the report for why that endpoint is left analyzed-not-bound).
func v5extBreakGlassOps() []opSpec {
	return []opSpec{
		{
			name: "breakglass.revoke", row: "RevokeBreakGlass", targets: projTargets,
			// #4546: core refuses an inactive actor (requireActorActive) but still does
			// not check roles.assign, so its leg feeds TestCoreRefusesSuspendedActor
			// only and stays out of both oracles.
			coreGateExcluded: true,
			req:              atP("roles.assign"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.RevokeBreakGlass(ctx, p.userID, p.machineID, pp.projectID, pp.breakGlassActivationID)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/revoke", pp.projectID, pp.breakGlassActivationID), nil}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := pb.NewBreakGlassServiceClient(lg.conn).RevokeBreakGlass(ctx, &pb.RevokeBreakGlassRequest{
					ProjectId: uint32(pp.projectID), ActivationId: uint32(pp.breakGlassActivationID)})
				return err
			},
		},
	}
}

// isV5extOp reports whether name is one of the V5EXT bindings.
func isV5extOp(name string) bool {
	for _, s := range v5extOps() {
		if s.name == name {
			return true
		}
	}
	return false
}
