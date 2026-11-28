package authzdiff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5EXT6B op: mfa.enroll (BeginMFAEnrollment).
//
// POST /api/v1/auth/mfa/enroll:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core gate: an at-rest auth encryptor must be enabled (wired in the harness since
//	           V5EXT6B — see world_test.go), and user.MFAEnabled must be false; a user
//	           with mfa_enabled=true is refused ErrMFAAlreadyEnabled → HTTP 400 (a
//	           client-safe message), which maps to PreconditionFailed.
//	Model:    noMFARequired:true, accountState:true — only pkMFAUser has mfa_enabled=true
//	           in the fixture, so only it is refused (PreconditionFailed); every other
//	           authenticated user without MFA is Allowed (a pending enrolment does
//	           NOT disqualify, so pkMFAEnrollee is Allowed too). A machine token has no
//	           user account: 400 "user not found" → PreconditionFailed. A restricted PAT is
//	           Denied (POST /auth/mfa/enroll is in core's restricted-PAT write-refusal
//	           table), a suspended actor is Denied.
//	core_refusal: "none" (matrix.json) → coreEnforced=false; coreGateExcluded=true →
//	           core excluded from Oracle 1/2 (BeginMFAEnrollment checks only the
//	           encryptor + the MFAEnabled business rule, not an RBAC gate).
//	restOK:   otpauth_uri is non-empty in the response.
//
// What this oracle does NOT verify:
//   - BlockWhenImpersonating: verified structurally by TestMFARouteGatesPresent.
//   - Cryptographic validity of the TOTP URI (only non-empty is checked), or that the
//     returned secret validates against a TOTP code.
//   - Idempotency: calling twice re-generates the pending secret (upsert behaviour).
func v5ext6bOps() []opSpec {
	return mfaEnrollOps()
}

func mfaEnrollOps() []opSpec {
	return []opSpec{
		{
			name:             "mfa.enroll",
			row:              "BeginMFAEnrollment",
			preconditionMsgs: []string{"MFA is already enabled", "user not found"},
			targets:          []tgt{tA}, // self-service, no project target
			// controlAs: pkGlobalAdmin has no MFA enabled → BeginMFAEnrollment succeeds.
			controlAs: []principalKind{pkGlobalAdmin},
			req: func(_ *fixtures, _ tgt, _ byte) requirement {
				return requirement{noMFARequired: true, accountState: true}
			},
			// coreGateExcluded=true: core enforces only the encryptor + MFAEnabled
			// business rule, not an RBAC gate. Core leg pattern: success → nil (Allowed,
			// kept out of Oracle 1/2); ErrPermissionDenied → returned; any other
			// business-rule error (ErrMFAAlreadyEnabled) → errNotAuthzLayer.
			coreGateExcluded: true,
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				if _, _, err := lg.c.BeginMFAEnrollment(ctx, p.userID); err != nil {
					if errors.Is(err, core.ErrPermissionDenied) {
						return err
					}
					return errNotAuthzLayer
				}
				return nil
			},
			rest: func(_ *fixtures, _ tgt, _ byte) restReq {
				return restReq{http.MethodPost, "/api/v1/auth/mfa/enroll", nil}
			},
			restOK: func(b []byte, _ *fixtures, _ tgt) bool {
				var env struct {
					Data struct {
						OTPAuthURI string `json:"otpauth_uri"`
					} `json:"data"`
				}
				_ = json.Unmarshal(b, &env)
				return env.Data.OTPAuthURI != ""
			},
		},
	}
}

// isV5ext6bOp reports whether name is one of the V5EXT6B bindings.
func isV5ext6bOp(name string) bool {
	for _, s := range v5ext6bOps() {
		if s.name == name {
			return true
		}
	}
	return false
}
