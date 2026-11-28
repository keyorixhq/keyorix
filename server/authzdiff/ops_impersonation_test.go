package authzdiff

import (
	"context"
	"fmt"
	"net/http"
)

// Stage-3 ops (V5EXT8/9): impersonation.start, impersonation.end, webauthn.deleteCredential.
//
// All three are REST-only (no gRPC surface) and have core_refusal="none" in
// matrix.json, so coreEnforced=false: the core leg is run and recorded but
// excluded from Oracle 1 and Oracle 2 comparison.
//
// # impersonation.start (StartImpersonation)
//
// POST /api/v1/admin/impersonate:
//
//	Route:  RequirePermission("users.impersonate") — global scope (admin-bypass
//	        roles only). The route gate is load-bearing.
//	Core:   StartImpersonation enforces session-auth and the admin-rank ceiling
//	        (requireEqualOrGreaterAdminAuthority) but does NOT Authorize the
//	        users.impersonate permission itself. coreEnforced=false. The harness
//	        actorCtx() does not set WithSessionAuth, so sessionAuthFromContext
//	        defaults to true and the session-auth path never fires here.
//	Model:  globalPerms:["users.impersonate"], humanOnly:true.
//
// # impersonation.end (EndImpersonation)
//
// POST /api/v1/auth/end-impersonation:
//
//	Route:  None — no RequirePermission gate. The session-state check is in core.
//	Core:   EndImpersonation refuses unless session.ImpersonatedBy != nil.
//	        coreEnforced=false. The core leg always uses impersonationEndToken (the
//	        fixture impersonation session), not the named principal's token.
//	Model:  impersonatingSession:true, humanOnly:true. Only pkImpersonating (the
//	        controlAs positive control) satisfies it; every other principal's
//	        regular session gets HTTP 400 (PreconditionFailed).
//
// # webauthn.deleteCredential (DeleteWebAuthnCredential)
//
// DELETE /api/v1/auth/webauthn/credentials/{id}:
//
//	Route:  BlockWhenImpersonating only — no RBAC gate.
//	Core:   requireReauth (TOTP or passkey) then storage delete. coreEnforced=false.
//	Model:  mfaRequired:true. Only pkMFAUser satisfies it (mfa_enabled=true); the
//	        credential fixture belongs to pkMFAUser and the legs pass
//	        mfaUserTOTPSecret. Every other principal fails requireReauth → HTTP 400.
//
// What these oracles do NOT verify:
//   - impersonation.start: the session-auth refusal (actorCtx defaults sessionAuth
//     true); cookie/AdminSessionCookieName stash; requireEqualOrGreaterAdminAuthority
//     when the target holds admin roles (fixture u-target holds only project_viewer).
//   - impersonation.end: session expiry re-check; the cookie-swap "Return to Admin"
//     path; the admin-side authority re-check during the session.
//   - webauthn.deleteCredential: the WebAuthn passkey assertion path (webauthnRP is
//     nil in the harness; FinishWebAuthnReauth deferred); BeginWebAuthnRegistration /
//     ListWebAuthnCredentials (deferred).
func impersonationOps() []opSpec {
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
			name: "impersonation.end", row: "EndImpersonation", targets: []tgt{tGlobal},
			req: func(*fixtures, tgt, byte) requirement {
				return requirement{impersonatingSession: true, humanOnly: true, accountState: true}
			},
			preconditionMsgs: []string{"impersonation session"},
			// Core leg always uses impersonationEndToken (the fixture impersonation
			// session), regardless of p — coreEnforced=false, so the result is recorded
			// but not checked by either oracle.
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
				return requirement{mfaRequired: true, accountState: true}
			},
			preconditionMsgs: mfaPreconditionMsgs,
			// Core leg uses p.userID and pkMFAUser's TOTP code. For non-pkMFAUser
			// principals, requireReauth fails → Other; coreEnforced=false.
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
	}
}

// isImpersonationOp reports whether name is covered by TestImpersonationStrictSweep.
func isImpersonationOp(name string) bool {
	switch name {
	case "impersonation.start", "impersonation.end", "webauthn.deleteCredential":
		return true
	}
	return false
}
