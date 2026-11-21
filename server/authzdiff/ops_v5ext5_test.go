package authzdiff

import (
	"context"
	"encoding/json"
	"net/http"
)

// V5EXT5 ops: MFA activate, disable, and recovery-codes regenerate.
//
// # mfa.activate (ActivateMFA)
//
// POST /api/v1/auth/mfa/activate:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/activate", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core gate: requireReauth(password) + GetMFASecret(pending enrollment check).
//	           Fails "no pending MFA enrolment" for principals without a pending row.
//	Model:    pendingMFARequired: true — only pkMFAEnrollee has an Activated=false
//	          mfa_secrets row in the fixture.
//	core_refusal: "none" (matrix.json) → coreEnforced=false → core excluded from Oracle 1.
//	restOK:   recovery_codes is non-empty in the response.
//
// What this oracle does NOT verify:
//   - BlockWhenImpersonating: verified structurally by TestMFARouteGatesPresent.
//   - Recovery-code correctness (non-empty list, not cryptographic validity).
//   - Session purge after activation (other sessions revoked for security upgrade).
//   - MFAEnrolmentRequired flag clearing (#3799).
//
// # mfa.disable (DisableMFA)
//
// POST /api/v1/auth/mfa/disable:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/disable", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core gate: user.MFAEnabled check (before reauth) + requireReauth(code).
//	           Returns "MFA is not enabled" for principals without mfa_enabled=true.
//	Model:    mfaRequired: true — only pkMFAUser has mfa_enabled=true in the fixture.
//	core_refusal: "none" → coreEnforced=false → core excluded from Oracle 1.
//
// What this oracle does NOT verify:
//   - BlockWhenImpersonating: verified structurally by TestMFARouteGatesPresent.
//   - Session purge after disable (all other sessions revoked for security downgrade).
//
// # mfa.recovery-codes.regenerate (RegenerateMFARecoveryCodes)
//
// POST /api/v1/auth/mfa/recovery-codes/regenerate:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/recovery-codes/regenerate", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core gate: user.MFAEnabled check + requireReauth(code). Same structure as mfa.disable.
//	Model:    mfaRequired: true — only pkMFAUser passes.
//	core_refusal: "none" → coreEnforced=false → core excluded from Oracle 1.
//	restOK:   recovery_codes is non-empty in the response.
//
// What this oracle does NOT verify:
//   - BlockWhenImpersonating: verified structurally by TestMFARouteGatesPresent.
//   - That the new codes replace the old ones (the oracle only checks non-empty).
//
// TOTP code anti-replay: each leg has its own fresh DB copy (template clone), so
// MarkTOTPStepUsed in one leg does not affect another.
func v5ext5Ops() []opSpec {
	return append(append(mfaActivateOps(), mfaDisableOps()...), mfaRegenerateOps()...)
}

// ---- mfa.activate ----

func mfaActivateOps() []opSpec {
	return []opSpec{
		{
			name:    "mfa.activate",
			row:     "ActivateMFA",
			targets: []tgt{tA}, // self-service, no project target; tA is the canonical single-target
			// controlAs: admin has no pending enrollment; pkMFAEnrollee does.
			controlAs: []principalKind{pkMFAEnrollee},
			req: func(_ *fixtures, _ tgt, _ byte) requirement {
				return requirement{pendingMFARequired: true}
			},
			// coreEnforced=false (core_refusal="none") → excluded from Oracle 1.
			// Core leg for Oracle 2: ActivateMFA(userID, code, password, "").
			// - pkMFAEnrollee: requireReauth(password, MFAEnabled=false) → ok; GetMFASecret → pending row; validate code → Allowed.
			// - Others (no pending row): requireReauth succeeds then GetMFASecret fails → Denied.
			// - pkMFAUser: requireReauth(MFAEnabled=true, password alone) → no step-up grant → Denied.
			// - Machines/system actor: errNotAuthzLayer.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				code := currentTOTPCode(lg.fx.mfaEnrolleeTOTPSecret)
				_, err := lg.c.ActivateMFA(ctx, p.userID, code, fxPassword, "")
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				// TOTP code is from the pending enrollment secret (mfaEnrolleeTOTPSecret).
				// All principals receive the same body; non-pkMFAEnrollee principals
				// fail at GetMFASecret before the code is ever evaluated.
				code := currentTOTPCode(fx.mfaEnrolleeTOTPSecret)
				return restReq{http.MethodPost, "/api/v1/auth/mfa/activate",
					map[string]any{"code": code, "password": fxPassword}}
			},
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				var env struct {
					Data struct {
						RecoveryCodes []string `json:"recovery_codes"`
					} `json:"data"`
				}
				_ = json.Unmarshal(b, &env)
				return len(env.Data.RecoveryCodes) > 0
			},
		},
	}
}

// ---- mfa.disable ----

func mfaDisableOps() []opSpec {
	return []opSpec{
		{
			name:    "mfa.disable",
			row:     "DisableMFA",
			targets: []tgt{tA}, // self-service, no project target
			// controlAs: admin has mfa_enabled=false; pkMFAUser does not.
			controlAs: []principalKind{pkMFAUser},
			req: func(_ *fixtures, _ tgt, _ byte) requirement {
				return requirement{mfaRequired: true}
			},
			// coreEnforced=false → excluded from Oracle 1.
			// Core leg: DisableMFA(userID, codeOrPassword, "").
			// - pkMFAUser: user.MFAEnabled=true → requireReauth(TOTP code) → ok → Allowed.
			// - Others: user.MFAEnabled=false → "MFA is not enabled" → Denied.
			// - Machines/system actor: errNotAuthzLayer.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				code := currentTOTPCode(lg.fx.mfaUserTOTPSecret)
				return lg.c.DisableMFA(ctx, p.userID, code, "")
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaUserTOTPSecret)
				return restReq{http.MethodPost, "/api/v1/auth/mfa/disable",
					map[string]any{"code": code}}
			},
		},
	}
}

// ---- mfa.recovery-codes.regenerate ----

func mfaRegenerateOps() []opSpec {
	return []opSpec{
		{
			name:    "mfa.recovery-codes.regenerate",
			row:     "RegenerateMFARecoveryCodes",
			targets: []tgt{tA}, // self-service, no project target
			// controlAs: only pkMFAUser has mfa_enabled=true.
			controlAs: []principalKind{pkMFAUser},
			req: func(_ *fixtures, _ tgt, _ byte) requirement {
				return requirement{mfaRequired: true}
			},
			// coreEnforced=false → excluded from Oracle 1.
			// Core leg: RegenerateMFARecoveryCodes(userID, codeOrPassword).
			// - pkMFAUser: user.MFAEnabled=true → requireReauth(TOTP code) → ok → returns codes.
			// - Others: user.MFAEnabled=false → "MFA is not enabled" → Denied.
			// - Machines/system actor: errNotAuthzLayer.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				code := currentTOTPCode(lg.fx.mfaUserTOTPSecret)
				_, err := lg.c.RegenerateMFARecoveryCodes(ctx, p.userID, code)
				return err
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaUserTOTPSecret)
				return restReq{http.MethodPost, "/api/v1/auth/mfa/recovery-codes/regenerate",
					map[string]any{"code": code}}
			},
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				var env struct {
					Data struct {
						RecoveryCodes []string `json:"recovery_codes"`
					} `json:"data"`
				}
				_ = json.Unmarshal(b, &env)
				return len(env.Data.RecoveryCodes) > 0
			},
		},
	}
}

// isV5ext5Op reports whether name is one of the V5EXT5 bindings.
func isV5ext5Op(name string) bool {
	for _, s := range v5ext5Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
