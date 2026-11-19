package authzdiff

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/keyorixhq/keyorix/internal/core"
)

// V5EXT6B ops: MFA enroll (BeginMFAEnrollment).
//
// # mfa.enroll (BeginMFAEnrollment)
//
// POST /api/v1/auth/mfa/enroll:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core gate: authEncryptor must be enabled + user.MFAEnabled must be false.
//	           Returns "MFA already enabled" for principals with mfa_enabled=true.
//	Model:    noMFARequired: true — only pkMFAUser has mfa_enabled=true in the fixture.
//	core_refusal: not in matrix.json → coreEnforced=false; coreGateExcluded=true →
//	              core excluded from Oracle 1/2.
//	restOK:   otpauth_uri is non-empty in the response.
//
// What this oracle does NOT verify:
//   - BlockWhenImpersonating: verified structurally by TestMFARouteGatesPresent.
//   - Cryptographic validity of the TOTP URI (only non-empty is checked).
//   - That the returned secret actually validates against a TOTP code.
//   - Idempotency: calling twice re-generates the pending secret (upsert behavior).
func v5ext6bOps() []opSpec {
	return mfaEnrollOps()
}

// ---- mfa.enroll ----

func mfaEnrollOps() []opSpec {
	return []opSpec{
		{
			name:    "mfa.enroll",
			row:     "BeginMFAEnrollment",
			targets: []tgt{tA}, // self-service, no project target
			// controlAs: pkGlobalAdmin has no MFA enabled → BeginMFAEnrollment succeeds.
			controlAs: []principalKind{pkGlobalAdmin},
			req: func(_ *fixtures, _ tgt, _ byte) requirement {
				return requirement{noMFARequired: true}
			},
			// coreGateExcluded=true: core enforces only the authEncryptor check and
			// user.MFAEnabled business rule — not an RBAC gate. Excluded from Oracle
			// 1/2; participates only via the named-principal sweep.
			// Core leg pattern:
			//   - pkMFAUser active: ErrMFAAlreadyEnabled → errNotAuthzLayer.
			//   - Others active: succeeds → nil (Allowed, ignored by Oracle 1/2).
			//   - Machines/system actor: errNotAuthzLayer.
			coreGateExcluded: true,
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				_, _, err := lg.c.BeginMFAEnrollment(ctx, p.userID)
				if err != nil {
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
