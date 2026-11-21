package authzdiff

import (
	"context"
	"fmt"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5EXT9 ops: impersonation.end, webauthn.deleteCredential, mfaReset.request,
// mfaReset.approve.
//
// All four have core_refusal="none" in matrix.json: coreEnforced=false. The core
// leg is run and recorded but excluded from Oracle 1 and Oracle 2 comparison.
//
// # impersonation.end (EndImpersonation)
//
// POST /api/v1/auth/end-impersonation:
//
//	Route:  None — no RequirePermission gate on this route. Session-auth and
//	        machine/PAT checks are in the handler.
//	Core:   EndImpersonation checks session.ImpersonatedBy != nil. No RBAC.
//	        coreEnforced=false.
//	Model:  impersonatingSession: true, humanOnly: true. The only principal
//	        satisfying this is pkImpersonating (the controlAs positive control).
//	        Every other named principal's token is a regular (non-impersonating)
//	        session and the handler returns 400 "not an impersonation session".
//
//	What the oracle does NOT verify: session expiry re-check;
//	cookie-swap ("Return to Admin") path; requireEqualOrGreaterAdminAuthority
//	re-check on the admin side during the session.
//
// # webauthn.deleteCredential (DeleteWebAuthnCredential)
//
// DELETE /api/v1/auth/webauthn/credentials/{id}:
//
//	Route:  BlockWhenImpersonating only — no RBAC gate.
//	Core:   requireReauth (TOTP or passkey re-auth) then storage delete.
//	        coreEnforced=false.
//	Model:  mfaRequired: true. Only pkMFAUser satisfies this (mfa_enabled=true).
//	        The credential fixture belongs to pkMFAUser; the core/REST legs pass
//	        mfaUserTOTPSecret as proof. For every other principal requireReauth
//	        fails → HTTP 400.
//
//	What the oracle does NOT verify: WebAuthn passkey assertion path (requires
//	webauthnRP, nil in this harness; FinishWebAuthnReauth is deferred);
//	BeginWebAuthnRegistration / ListWebAuthnCredentials (also deferred).
//
// # mfaReset.request (RequestMFAReset)
//
// POST /api/v1/mfa-reset-requests:
//
//	Route:  RequirePermission(permUsersWrite) — global scope.
//	Core:   requireMFAResetActor (human, globalAdminRole, secondFactor), then
//	        requireReauth (TOTP). coreEnforced=false.
//	Model:  globalAdminRole: true, humanOnly: true, mfaRequired: true.
//	        Positive control: pkMFAResetActor (global admin + TOTP enrolled).
//
//	HARDENING-V5EXT9-1: the route gate (users.write@global) is WEAKER than
//	core's requireMFAResetActor (global-admin-role + TOTP second factor). A user
//	holding users.write@global but no admin role is denied at core (ErrMFAResetAdminRequired →
//	403) where the model agrees (no globalAdminRole → Denied). No plant added
//	for this HARDENING: the TOTP requirement makes a curated-variation plant
//	impractical without a third dedicated TOTP fixture user.
//
//	What the oracle does NOT verify: refuseIfMFAResetPending duplicate guard;
//	eligibleMFAResetApprovers count; requireReauth anti-replay; dual-control
//	requester != approver (covered by mfaReset.approve).
//
// # mfaReset.approve (ApproveMFAReset)
//
// POST /api/v1/mfa-reset-requests/{id}/approve:
//
//	Route:  RequirePermission(permUsersWrite) — global scope.
//	Core:   requireMFAResetActor, then dual-control checks, then requireReauth.
//	        coreEnforced=false.
//	Model:  globalAdminRole: true, humanOnly: true, mfaRequired: true.
//	        Positive control: pkMFAResetActor (the approver; requester is
//	        u-v9-mfa-admin-b, a different admin → dual-control always satisfied
//	        for pkMFAResetActor).
//
//	What the oracle does NOT verify: refuseMFAResetRequesterChanged; refuseMFAResetTarget;
//	requireReauth anti-replay; self-approval refusal; request expiry.
func v5ext9Ops() []opSpec {
	return []opSpec{
		{
			name: "impersonation.end", row: "EndImpersonation", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{impersonatingSession: true, humanOnly: true}
			},
			// Core leg always uses impersonationEndToken (the fixture impersonation
			// session), regardless of p — coreEnforced=false so the result is
			// recorded but not checked by either oracle.
			core: func(ctx context.Context, lg *leg, _ *principal, _ tgt, _ byte) error {
				_, err := lg.c.EndImpersonation(ctx, lg.fx.impersonationEndToken)
				return err
			},
			controlAs: []principalKind{pkImpersonating},
			rest: func(_ *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, "/api/v1/auth/end-impersonation", nil}
			},
		},
		{
			name: "webauthn.deleteCredential", row: "DeleteWebAuthnCredential", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{mfaRequired: true}
			},
			// Core leg uses pkMFAUser's userID and TOTP secret. For non-pkMFAUser
			// principals, requireReauth fails (no TOTP) → Other; coreEnforced=false.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				code := currentTOTPCode(lg.fx.mfaUserTOTPSecret)
				return lg.c.DeleteWebAuthnCredential(ctx, p.userID, lg.fx.webAuthnCredentialID, code)
			},
			controlAs: []principalKind{pkMFAUser},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaUserTOTPSecret)
				return restReq{
					http.MethodDelete,
					fmt.Sprintf("/api/v1/auth/webauthn/credentials/%d", fx.webAuthnCredentialID),
					map[string]any{"code": code},
				}
			},
		},
		{
			name: "mfaReset.request", row: "RequestMFAReset", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalAdminRole: true, humanOnly: true, mfaRequired: true}
			},
			// Core leg: p.userID drives requireMFAResetActor. The TOTP code is from
			// mfaResetActorTOTPSecret and is only valid for pkMFAResetActor; all other
			// principals fail at requireMFAResetActor before reaching requireReauth.
			// freshUserID is the target (no prior pending request in the template).
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				code := currentTOTPCode(lg.fx.mfaResetActorTOTPSecret)
				_, err := lg.c.RequestMFAReset(ctx, p.userID, p.isMachine(), core.MFAResetRequestInput{
					User:       fmt.Sprintf("%d", lg.fx.freshUserID),
					Reason:     "harness test request",
					VerifiedBy: "ticket",
					Evidence:   "harness-v5ext9",
					Code:       code,
				})
				return err
			},
			controlAs: []principalKind{pkMFAResetActor},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaResetActorTOTPSecret)
				return restReq{
					http.MethodPost,
					"/api/v1/mfa-reset-requests",
					map[string]any{
						"user":        fmt.Sprintf("%d", fx.freshUserID),
						"reason":      "harness test request",
						"verified_by": "ticket",
						"evidence":    "harness-v5ext9",
						"code":        code,
					},
				}
			},
		},
		{
			name: "mfaReset.approve", row: "ApproveMFAReset", targets: []tgt{tGlobal}, globalHandler: true,
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{globalAdminRole: true, humanOnly: true, mfaRequired: true}
			},
			// Core leg: targets mfaResetRequestV9ID (requester=u-v9-mfa-admin-b,
			// target=u-v9-mfa-reset-target). pkMFAResetActor ≠ requester →
			// dual-control passes for pkMFAResetActor. All other principals fail at
			// requireMFAResetActor before reaching dual-control or requireReauth.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				code := currentTOTPCode(lg.fx.mfaResetActorTOTPSecret)
				_, err := lg.c.ApproveMFAReset(ctx, p.userID, p.isMachine(), lg.fx.mfaResetRequestV9ID, code)
				return err
			},
			controlAs: []principalKind{pkMFAResetActor},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaResetActorTOTPSecret)
				return restReq{
					http.MethodPost,
					fmt.Sprintf("/api/v1/mfa-reset-requests/%d/approve", fx.mfaResetRequestV9ID),
					map[string]any{"code": code},
				}
			},
		},
	}
}
