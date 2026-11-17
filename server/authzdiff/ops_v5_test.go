package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	pb "github.com/keyorixhq/keyorix/server/proto/pb"
)

// V5 ops: authorization-completeness extension of the harness over operations
// the earlier phases deferred with a "model:"/"design: bulk … not bound" reason.
// Every op here is bound ONLY where the authorization decision the three layers
// make is a plain scoped-permission check the reference model already expresses
// (perms @ scope, possibly + a global perm). The business state machines these
// endpoints also run (break-glass activation lifecycle, access-review campaign
// states, risk-exception approval flow) are NOT authorization decisions the
// layers can disagree on and are deliberately left to each layer — the model
// only decides allow/deny of the gate, exactly as for the earlier families.
//
// Every binding is validated by its admin positive control (OUTCOMES.md
// precondition 2) and red-proved by dropping its gate in a scratch copy; a
// binding whose control does not pass is dropped from the oracle (uncalibrated
// → the run fails), so none can silently empty the oracle.
func v5Ops() []opSpec {
	return append(v5BulkSecretOps(), v5BreakGlassOps()...)
}

// ---- area 2: break-glass activation (self-service emergency access) ----
//
// POST /api/v1/projects/{id}/break-glass carries NO RequireScopedPermission at
// the REST router (only BlockWhenImpersonating), and the gRPC RPC
// BreakGlassService.ActivateBreakGlass has no gate beyond requireUser (a user
// token): the ENTIRE authorization is core's, in ActivateBreakGlass, reached
// the same way from both transports. So this is the cleanest core-gated
// differential after reassign-owner — the transports agree with core by
// construction, and Oracle 2 checks core's real gate against the independent
// model.
//
// Core's gate (internal/core/break_glass.go:256-293), in order:
//  1. a restricted PAT is refused (ErrRestrictedPATCannotBreakGlass) — the
//     model gets this from core.RestrictedPATWriteRefusal (the route IS in the
//     table, pat_restriction_writes.go:106);
//  2. the policy must be enabled (newCore enables it with project_developer);
//  3. projectID/userID must be non-zero — a MACHINE actor (userID==0) is
//     refused with a VALIDATION error, mapped to `other` on both legs and
//     absorbed by the partition's known-09 waiver, never a disagreement;
//  4. a justification ≥10 chars (the binding always sends one);
//  5. IsProjectMember(userID, projectID) — a role scoped to THIS project,
//     direct or via a live group, NOT a global/install-wide role. The model's
//     memberOnly requirement is exactly this (memberOf).
//
// The global admin holds project_admin@A and @B (world_test.go), so it IS a
// project member: the positive control passes on both targets without a
// controlAs override.
func v5BreakGlassOps() []opSpec {
	return []opSpec{
		{
			name: "breakglass.activate", row: "ActivateBreakGlass", targets: projTargets,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{memberOnly: true, scope: pid(fx, t)}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.ActivateBreakGlass(ctx, pid(lg.fx, t), p.userID, "emergency-access-justification", "")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/break-glass", pid(fx, t)),
					map[string]any{"justification": "emergency-access-justification"}}
			},
			grpc: func(ctx context.Context, lg *leg, t tgt, _ byte) error {
				_, err := pb.NewBreakGlassServiceClient(lg.conn).ActivateBreakGlass(ctx, &pb.ActivateBreakGlassRequest{
					ProjectId: uint32(pid(lg.fx, t)), Justification: "emergency-access-justification"})
				return err
			},
		},
	}
}

// ---- area 1: bulk secret operations with a single project-scope gate ----
//
// Only reassign-owner gates once, at the project scope, in core
// (ReassignOwnedSecrets → AuthorizePrincipal roles.assign@project, before any
// per-secret work). The other bulk lifecycle ops (bulk-delete/-rename/-rotate,
// suspend-all, resume-all) authorize PER ITEM (ownership/share) in core and
// carry the project-wide secrets.write/secrets.delete gate only at the REST
// router, so core and REST authorize different questions — outside this model's
// domain (see the report's Findings). They are left with their reasons.
func v5BulkSecretOps() []opSpec {
	return []opSpec{
		{
			// POST /projects/{id}/secrets/reassign-owner:
			// {"from_owner_id":N,"to_owner_id":M}. Router gate permRolesAssign@project;
			// core re-checks the SAME roles.assign@project before any transfer
			// (secret_reassign_owner.go). No gRPC surface. The effect count may be 0
			// (no secret owned by from_owner), but the AUTHORIZATION decision is the
			// gate alone: a 2xx means the gate passed, so no restOK is needed.
			name: "secret.reassign.owner", row: "ReassignOwnedSecrets", targets: projTargets,
			req: atP("roles.assign"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				kind, id := principalActor(p)
				_, err := lg.c.ReassignOwnedSecrets(ctx, kind, id, pid(lg.fx, t), lg.fx.adminID, lg.fx.targetUserID)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/secrets/reassign-owner", pid(fx, t)),
					map[string]any{"from_owner_id": fx.adminID, "to_owner_id": fx.targetUserID}}
			},
		},
	}
}
