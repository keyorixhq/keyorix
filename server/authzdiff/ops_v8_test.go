package authzdiff

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// V8 ops: authorization-completeness extension over the access-review and
// risk-exception families the earlier phases deferred with a "model:" reason.
//
// Both ops bound here are PURE ROUTER-GATE differentials: the matrix marks their
// core row `core_refusal:"none"` (coreEnforced==false), so the core leg is
// recorded but excluded from both oracles (ID-2, transport-enforced), and Oracle 2
// checks the REST router's scoped-permission gate against the independent model —
// exactly the shape the existing `router-gate-removed` plant exercises. The
// business state machines these endpoints also run (campaign lifecycle / review
// item decisions, risk-exception dual-control / SoD-live-violation / sunset) are
// NOT authorization decisions the layers disagree on under the model and are left
// to each layer, exactly as for the earlier families.
//
// Every binding is validated by its admin positive control (OUTCOMES.md
// precondition 2) and red-proved by removing its router gate in a scratch overlay
// (plants_test.go); an uncalibrated binding fails a strict run, so none can
// silently empty the oracle.
func v8Ops() []opSpec {
	return append(v8AccessReviewOps(), v8RiskExceptionOps()...)
}

// ---- family 1: access review (open recertification campaign) ----
//
// POST /api/v1/projects/{id}/access-review/campaigns opens a recertification
// campaign. The router gates it with RequireScopedPermission(permRolesAssign,
// projectScope) (server/http/router.go). core.OpenAccessReviewCampaign performs
// NO authorization of its own — its own comment records that opening is NOT gated
// on a human actor because the scheduler legitimately auto-opens overdue campaigns
// as a system action (actorID==0); the attributable-human and reviewer-
// independence controls live on the DECISION endpoints (attest / revoke / decide),
// not on opening. So the matrix row is `core_refusal:"none"` and this is a clean
// router-gate differential: REST and the model are compared on roles.assign@project.
//
// The global admin holds project_admin@A and @B (world_test.go), so it holds
// roles.assign at both targets and the positive control passes without a controlAs
// override. No gRPC surface (matrix grpc:null), so the gRPC leg is NA (ID-3).
//
// Scope of this oracle: it checks the roles.assign@project GATE that decides
// whether a principal may open a campaign. It does NOT model the campaign
// lifecycle (item generation, degraded-audit snapshot, open/closed state), nor the
// reviewer-independence / human-reviewer / grant-exists controls on the attest /
// revoke / decide endpoints (those are `core_refusal:"typed"` and authorize a
// different question than the project gate — left analyzed-not-bound, see the
// report), nor the close endpoint's force-close independence.
func v8AccessReviewOps() []opSpec {
	return []opSpec{
		{
			name: "access-review.campaign.open", row: "OpenAccessReviewCampaign", targets: projTargets,
			req: atP("roles.assign"),
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				_, err := lg.c.OpenAccessReviewCampaign(ctx, p.userID, p.machineID, pid(lg.fx, t), "synthetic-campaign")
				return err
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/projects/%d/access-review/campaigns", pid(fx, t)),
					map[string]any{"name": "synthetic-campaign"}}
			},
		},
	}
}

// ---- family 2: risk exceptions (create a governed risk acceptance) ----
//
// POST /api/v1/risk-exceptions records a time-bound acceptance of a control gap.
// The router gates it with RequirePermission(permSystemWrite) at GLOBAL scope
// (server/http/router.go). core.CreateRiskException performs no permission check
// (matrix row `core_refusal:"none"`); it enforces only business rules — human-only
// (a machine is refused with an untyped error), a title+justification, a valid
// category, a future, bounded expiry, and — ONLY when category=="sod" — that the
// reference is a LIVE separation-of-duties violation. This binding uses the
// non-sod category "other", so the SoD-live-violation path is not taken and the
// only authorization that varies by principal is the router's system.write@global
// gate: a clean global-scope router-gate differential, core leg excluded (ID-2).
//
// The global admin holds the install-wide admin role (bypasses_permission_checks),
// which satisfies system.write@global and is a human, so the positive control
// passes. A MACHINE never holds system.write@global in the fixtures (a machine
// role is always project-scoped — applyVariation forbids a global machine grant),
// so the model denies every machine case and no over-denial (model-allows /
// REST-denies-on-human-only) can arise. No gRPC surface (matrix grpc:null).
//
// Scope of this oracle: it checks the system.write@global GATE that decides who
// may file a risk exception. It does NOT model the dual-control (creator≠approver,
// human-only) on /approve, the creator-or-admin rule on DELETE, the SoD-live-
// violation validation (category=="sod"), or the sunset/expiry bounds — those are
// left analyzed-not-bound (see the report).
func v8RiskExceptionOps() []opSpec {
	return []opSpec{
		{
			name: "riskexception.create", row: "CreateRiskException", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalPerms: []string{"system.write"}}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, err := lg.c.CreateRiskException(ctx, p.userID, p.isMachine(),
					"synthetic-title", "other", "synthetic-ref", "synthetic-justification-text", riskExceptionExpiry())
				return err
			},
			rest: func(*fixtures, tgt, byte) restReq {
				return restReq{http.MethodPost, "/api/v1/risk-exceptions", map[string]any{
					"title": "synthetic-title", "category": "other", "reference": "synthetic-ref",
					"justification": "synthetic-justification-text", "expires_at": riskExceptionExpiry().Format(time.RFC3339),
				}}
			},
		},
	}
}

// riskExceptionExpiry is a fixed future, bounded instant that satisfies
// CreateRiskException's sunset rule on every leg (the handler and the core call
// both receive the same value, so REST and the core leg agree on validity).
func riskExceptionExpiry() time.Time { return time.Now().UTC().Add(24 * time.Hour) }

// isV8Op reports whether name is one of the V8 bindings (used by the V8 strict
// sweep's no-gRPC fast path and its guard test).
func isV8Op(name string) bool {
	for _, s := range v8Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
