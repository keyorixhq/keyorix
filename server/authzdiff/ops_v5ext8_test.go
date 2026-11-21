package authzdiff

import (
	"context"
	"fmt"
	"net/http"
)

// V5EXT8 ops: impersonation.start and mfaReset.cancel.
//
// Both are REST-only (no gRPC surface). Both have core_refusal="none" in
// matrix.json, so coreEnforced=false: the core leg is run and recorded but
// excluded from Oracle 1 and Oracle 2 comparison.
//
// # impersonation.start (StartImpersonation)
//
// POST /api/v1/admin/impersonate:
//
//	Route:  RequirePermission("users.impersonate") — global scope.
//	        Only global admins hold this permission (admin-bypass).
//	Core:   StartImpersonation enforces session-auth (sessionAuthFromContext)
//	        and admin-rank-ceiling (requireEqualOrGreaterAdminAuthority), but
//	        does NOT call Authorize for the users.impersonate permission itself.
//	        coreEnforced=false (core_refusal:"none"). The harness actorCtx()
//	        does not set WithSessionAuth, so sessionAuthFromContext defaults to
//	        true for all principals; the session-auth check never fires here.
//	Model:  globalPerms: ["users.impersonate"], humanOnly: true.
//
// # mfaReset.cancel (CancelMFAReset)
//
// POST /api/v1/mfa-reset-requests/{id}/cancel:
//
//	Route:  RequirePermission(permUsersWrite) — global scope.
//	Core:   CancelMFAReset checks actorIsMachine||actorID==0, then
//	        isGlobalAdminRoleName. The route gate is WEAKER than core (see
//	        HARDENING-V5EXT8-1 in the report). coreEnforced=false
//	        (core_refusal:"none"). The effective gate is core's admin-role check.
//	Model:  globalAdminRole: true, humanOnly: true.
//	        (Captures the effective gate, not the route's weaker claim.)
//
// What these oracles do NOT verify:
//   - impersonation.start: session-auth check (harness actorCtx defaults
//     sessionAuth to true; no principal exercises the non-session-auth path);
//     cookie-setting / AdminSessionCookieName stash; requireEqualOrGreaterAdminAuthority
//     when target holds admin roles (fixture u-target holds only project_viewer).
//   - mfaReset.cancel: requireReauth TOTP gate on RequestMFAReset/ApproveMFAReset
//     (those endpoints remain deferred); status-transition guards; self-cancel check.
func v5ext8Ops() []opSpec {
	return []opSpec{
		{
			name: "impersonation.start", row: "StartImpersonation", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalPerms: []string{"users.impersonate"}, humanOnly: true}
			},
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				_, _, err := lg.c.StartImpersonation(ctx, p.userID, lg.fx.targetUserID, "127.0.0.1")
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, "/api/v1/admin/impersonate", map[string]any{"user_id": fx.targetUserID}}
			},
		},
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
	}
}
