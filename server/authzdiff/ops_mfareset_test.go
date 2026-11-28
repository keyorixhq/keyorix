package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// Stage-4 ops (V5EXT8/9): mfaReset.cancel, mfaReset.request, mfaReset.approve.
//
// All three are REST-only (no gRPC surface), all have core_refusal="none" in
// matrix.json (coreEnforced=false: the core leg is recorded but excluded from the
// oracle), and all carry globalHandler:true (their routes are served through
// package-level handler globals; the REST leg re-points them under routerMu).
//
// For all three the route gate is RequirePermission(permUsersWrite) → users.write
// at GLOBAL scope, which is WEAKER than the core's effective gate (an admin-named
// role at global scope, plus — for request/approve — a second factor). This is
// HARDENING-V5EXT8/9-1 (documented in the report, not a reachable bypass: core
// always runs after the route and enforces the stronger check). The model captures
// the EFFECTIVE gate (globalAdminRole), not the route's weaker users.write claim,
// so the curated pkCustom variation (users.write@global, no admin role) is Denied
// by core where the model agrees.
//
// # mfaReset.cancel (CancelMFAReset)
//
// POST /api/v1/mfa-reset-requests/{id}/cancel:
//
//	Core:  isGlobalAdminRoleName (admin-named role at global scope). No second factor.
//	Model: globalAdminRole:true, humanOnly:true. Positive control: pkGlobalAdmin.
//
// # mfaReset.request (RequestMFAReset)
//
// POST /api/v1/mfa-reset-requests:
//
//	Core:  requireMFAResetActor (human + globalAdminRole + a second factor enrolled),
//	       then requireReauth (TOTP). An admin WITHOUT a second factor is refused
//	       HTTP 403 (ErrMFAResetActorNeedsMFA) — a hard denial, NOT a 400 precondition,
//	       so mfaRequired is modelled as a plain deny (no accountState).
//	Model: globalAdminRole:true, humanOnly:true, mfaRequired:true.
//	       Positive control: pkMFAResetActor (global admin + TOTP). The target is
//	       freshUserID (no prior pending request). A second eligible approver
//	       (u-v9-mfa-admin-b) exists so ErrMFAResetNoSecondAdmin never fires.
//
// # mfaReset.approve (ApproveMFAReset)
//
// POST /api/v1/mfa-reset-requests/{id}/approve:
//
//	Core:  requireMFAResetActor, dual-control (approver != requester), then requireReauth.
//	Model: globalAdminRole:true, humanOnly:true, mfaRequired:true.
//	       Positive control: pkMFAResetActor (the approver); the pre-seeded request
//	       mfaResetRequestV9ID was requested by u-v9-mfa-admin-b, so dual control holds.
//
// What these oracles do NOT verify:
//   - the HARDENING-V5EXT8/9-1 route-vs-core gap with a plant (the TOTP second-factor
//     requirement would need a third dedicated TOTP fixture user — TODO-ISSUE); the
//     curated pkCustom variation shows the gap is an observable Denied, not a silent pass.
//   - mfaReset.cancel: status-transition guards (already decided/expired); the self-cancel
//     check (the requester is a non-probed admin).
//   - mfaReset.request: refuseIfMFAResetPending duplicate guard; requireReauth anti-replay.
//   - mfaReset.approve: refuseMFAResetRequesterChanged; refuseMFAResetTarget; self-approval
//     refusal; request expiry; requireReauth anti-replay.
func mfaResetOps() []opSpec {
	return []opSpec{
		{
			name: "mfaReset.cancel", row: "CancelMFAReset", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalAdminRole: true, humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				return lg.c.CancelMFAReset(ctx, p.userID, p.isMachine(), lg.fx.mfaResetRequestID)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/mfa-reset-requests/%d/cancel", fx.mfaResetRequestID), nil}
			},
		},
		{
			name: "mfaReset.request", row: "RequestMFAReset", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalAdminRole: true, humanOnly: true, mfaRequired: true}
			},
			controlAs: []principalKind{pkMFAResetActor},
			// Core: p.userID drives requireMFAResetActor. The TOTP code is valid only
			// for pkMFAResetActor; all other principals fail requireMFAResetActor before
			// reaching requireReauth. freshUserID is the target (no prior pending request).
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				code := currentTOTPCode(lg.fx.mfaResetActorTOTPSecret)
				_, err := lg.c.RequestMFAReset(ctx, p.userID, p.isMachine(), core.MFAResetRequestInput{
					User: fmt.Sprintf("%d", lg.fx.freshUserID), Reason: "harness test request",
					VerifiedBy: "ticket", Evidence: "harness-v5ext9", Code: code,
				})
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaResetActorTOTPSecret)
				return restReq{http.MethodPost, "/api/v1/mfa-reset-requests", map[string]any{
					"user": fmt.Sprintf("%d", fx.freshUserID), "reason": "harness test request",
					"verified_by": "ticket", "evidence": "harness-v5ext9", "code": code,
				}}
			},
		},
		{
			name: "mfaReset.approve", row: "ApproveMFAReset", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalAdminRole: true, humanOnly: true, mfaRequired: true}
			},
			controlAs: []principalKind{pkMFAResetActor},
			// Core: targets mfaResetRequestV9ID (requester=u-v9-mfa-admin-b). pkMFAResetActor
			// != requester → dual control holds. All other principals fail requireMFAResetActor.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				code := currentTOTPCode(lg.fx.mfaResetActorTOTPSecret)
				_, err := lg.c.ApproveMFAReset(ctx, p.userID, p.isMachine(), lg.fx.mfaResetRequestV9ID, code)
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaResetActorTOTPSecret)
				return restReq{http.MethodPost, fmt.Sprintf("/api/v1/mfa-reset-requests/%d/approve", fx.mfaResetRequestV9ID),
					map[string]any{"code": code}}
			},
		},
	}
}

// isMFAResetOp reports whether name is covered by TestMFAResetStrictSweep.
func isMFAResetOp(name string) bool {
	switch name {
	case "mfaReset.cancel", "mfaReset.request", "mfaReset.approve":
		return true
	}
	return false
}
