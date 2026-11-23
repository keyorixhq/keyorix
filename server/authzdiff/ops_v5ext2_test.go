package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5EXT2 ops: access-review attest/revoke, campaign decide/close, and
// break-glass review. These are the "leftover" ops from V5EXT that required
// either a harness change or additional fixtures.
//
// All five ops use projTargets (project A and B). Their fixtures live in
// perProject (world_test.go V5EXT2 section).
//
// HARNESS CHANGE (coreGateExcluded):
//
// For attest, revoke, decide, and review: core_refusal is "typed" (so the
// matrix-derived coreEnforced=true), BUT core does NOT re-check the router's
// permission gate. It enforces only reviewer-independence, human-only, and
// grant/activation state. Without coreGateExcluded, Oracle 1 and Oracle 2
// would fire O1/O2 disagreements for any no-permission principal: core allows
// (skips the permission check), REST denies (router gate fails), model denies
// (models the router gate + humanOnly). coreGateExcluded excludes the core leg
// from both oracles, leaving REST as the authoritative signal compared to the
// model. The core leg still runs and is recorded.
//
// MODEL RULE (humanOnly):
//
// All four coreGateExcluded ops require a human reviewer. Core's
// requireHumanReviewer refuses a machine actor (actorID==0 for machines). The
// model's humanOnly=true denies machines, so Oracle 2 matches what REST
// returns: the router gate might pass for a machine holding the permission, but
// the handler's core call returns 403 Denied. For suspend/expired/PAT cases,
// humanOnly has no effect (suspension and PAT are checked separately).
//
// CAMPAIGN.CLOSE (coreGateExcluded since #4546):
//
// CloseAccessReviewCampaign refuses an inactive acting account (core_refusal:
// "typed") but does not re-check roles.assign, so like the four ops above its
// core leg is excluded from both oracles and checked only by
// TestCoreRefusesSuspendedActor. The model is simply roles.assign@project.
//
// Red/green proofs for all five ops are in plants_test.go.
func v5ext2Ops() []opSpec {
	return append(accessReviewOps(), append(campaignOps(), breakGlassReviewOps()...)...)
}

// ---- standalone access-review: attest + revoke ----
//
// POST /api/v1/projects/{id}/access-review/attest: a reviewer certifies a grant
// (evidence-only, no state change). Router gate: RequireScopedPermission(roles.read,
// projectScope). Core: AttestAccessReviewGrant enforces humanOnly + reviewer-
// independence + grant-exists; it does NOT re-check roles.read. coreGateExcluded.
//
// POST /api/v1/projects/{id}/access-review/revoke: a reviewer removes a grant.
// Router gate: RequireScopedPermission(roles.assign, projectScope). Core:
// RevokeAccessReviewGrant enforces humanOnly + reviewer-independence + grant-exists
// + last-admin guard; it does NOT re-check roles.assign. coreGateExcluded.
//
// Both ops use the fixture perProject.accessReviewDecision, which targets
// u-target's project_viewer@project grant. u-target is never a probed principal,
// so reviewer-independence always passes. The grant is verified live (each fresh
// DB copy has it).
//
// Scope of these oracles: they check the router's permission gate on attest/revoke.
// They do NOT model: the SoD-live-violation re-check on approve, the campaign
// decision claim, the last-admin guard (revoke), or the reviewer-independence check
// (guaranteed by the fixture's choice of review target, not a modelled condition).
func accessReviewOps() []opSpec {
	return []opSpec{
		{
			name: "accessreview.attest", row: "AttestAccessReviewGrant", targets: projTargets,
			coreGateExcluded: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.read"}, scope: pid(fx, t), humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.AttestAccessReviewGrant(ctx, p.userID, pp.projectID, pp.accessReviewDecision)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/access-review/attest", pp.projectID),
					decisionBody(pp.accessReviewDecision)}
			},
		},
		{
			name: "accessreview.revoke", row: "RevokeAccessReviewGrant", targets: projTargets,
			coreGateExcluded: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.RevokeAccessReviewGrant(ctx, p.userID, pp.projectID, pp.accessReviewDecision)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/access-review/revoke", pp.projectID),
					decisionBody(pp.accessReviewDecision)}
			},
		},
	}
}

// decisionBody builds the JSON-serializable body for an attest/revoke request.
func decisionBody(d core.AccessReviewDecision) map[string]any {
	return map[string]any{
		"source":         d.Source,
		"principal_type": d.PrincipalType,
		"principal_id":   d.PrincipalID,
		"role_id":        d.RoleID,
	}
}

// ---- campaign: decide + close ----
//
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/items/{itemId}/decide:
// a reviewer decides one campaign item (attest or revoke). Router gate:
// RequireScopedPermission(roles.assign, projectScope). Core: DecideAccessReviewItem
// enforces humanOnly + reviewer-independence + campaign/item lookup; it does NOT
// re-check roles.assign. coreGateExcluded.
//
// POST /api/v1/projects/{id}/access-review/campaigns/{campaignId}/close:
// freezes the campaign. Router gate: RequireScopedPermission(roles.assign, projectScope).
// Core: CloseAccessReviewCampaign does NOT enforce a permission gate; since #4546 it
// refuses an inactive acting account (core_refusal:typed), so its core leg runs with
// coreGateExcluded for TestCoreRefusesSuspendedActor. Close uses force=false on a fully-decided campaign so
// no items remain pending, avoiding the force-close-independence check entirely.
//
// Both use perProject.campaignProjectID (a minimal project: only u-target).
// decideCampaignID has one pending item (decideCampaignItemID); closeCampaignID has
// all items pre-decided (admin attested u-target's item in the seed).
//
// Scope of these oracles: they check the router's roles.assign@campaignProject gate.
// They do NOT model the campaign state machine, item-claim race, reviewer-independence
// (guaranteed by the fixture's choice of review target), or the force-close guard.
func campaignOps() []opSpec {
	return []opSpec{
		{
			name: "campaign.decide", row: "DecideAccessReviewItem", targets: projTargets,
			coreGateExcluded: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				pp := fx.proj(byte(t))
				return requirement{perms: []string{"roles.assign"}, scope: pp.campaignProjectID, humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.DecideAccessReviewItem(ctx, p.userID, pp.campaignProjectID, pp.decideCampaignID, pp.decideCampaignItemID, "attest", "")
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/access-review/campaigns/%d/items/%d/decide",
						pp.campaignProjectID, pp.decideCampaignID, pp.decideCampaignItemID),
					map[string]any{"action": "attest"}}
			},
		},
		{
			name: "campaign.close", row: "CloseAccessReviewCampaign", targets: projTargets,
			// #4546: core refuses an inactive actor (requireActorActive) but still does
			// not check roles.assign, so its leg feeds TestCoreRefusesSuspendedActor
			// only and stays out of both oracles.
			coreGateExcluded: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				pp := fx.proj(byte(t))
				return requirement{perms: []string{"roles.assign"}, scope: pp.campaignProjectID}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.CloseAccessReviewCampaign(ctx, p.userID, p.machineID, pp.campaignProjectID, pp.closeCampaignID, false)
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/access-review/campaigns/%d/close",
						pp.campaignProjectID, pp.closeCampaignID),
					map[string]any{"force": false}}
			},
		},
	}
}

// ---- break-glass: review (post-activation check) ----
//
// POST /api/v1/projects/{id}/break-glass/{activationId}/review: records that a
// reviewer examined a concluded activation. Router gate:
// RequireScopedPermission(roles.assign, projectScope) + BlockWhenImpersonating.
// Core: ReviewBreakGlass enforces humanOnly + self-review-independence +
// still-active refusal; it does NOT re-check roles.assign. coreGateExcluded.
//
// The activation must be CONCLUDED (not ACTIVE). The existing breakGlassActivationID
// is ACTIVE (for breakglass.revoke); reviewBGActivationID is a separate REVOKED
// activation (activated then immediately revoked in the seed by admin). The activator
// is u-bg (non-probed), so self-review never fires for probed principals.
//
// BlockWhenImpersonating: the harness's principal tokens are authentic (issued by
// core's Login/CreateMachineIdentity), not impersonation tokens — no impersonation
// session is ever active in the fixture, so BlockWhenImpersonating always passes
// for every probed principal. Its gate is NOT part of the model.
//
// No gRPC leg: matrix.json has grpc=null for ReviewBreakGlass.
//
// Scope of this oracle: it checks the roles.assign@project gate. It does NOT
// model the activation state machine, the self-review independence check
// (guaranteed by the fixture's choice of activator u-bg), or the BlockWhenImpersonating
// middleware.
func breakGlassReviewOps() []opSpec {
	const reviewNote = "synthetic-review-note-fixture-v5ext2"
	return []opSpec{
		{
			name: "breakglass.review", row: "ReviewBreakGlass", targets: projTargets,
			coreGateExcluded: true,
			req: func(fx *fixtures, t tgt, _ byte) requirement {
				return requirement{perms: []string{"roles.assign"}, scope: pid(fx, t), humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				pp := lg.fx.proj(byte(t))
				return lg.c.ReviewBreakGlass(ctx, p.userID, pp.projectID, pp.reviewBGActivationID, reviewNote)
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/break-glass/%d/review", pp.projectID, pp.reviewBGActivationID),
					map[string]any{"note": reviewNote}}
			},
		},
	}
}

// isV5ext2Op reports whether name is one of the V5EXT2 bindings.
func isV5ext2Op(name string) bool {
	for _, s := range v5ext2Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
