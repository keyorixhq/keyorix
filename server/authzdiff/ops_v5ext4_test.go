package authzdiff

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/pquerna/otp/totp"
)

// V5EXT4 ops: bulk-rotate and MFA step-up.
//
// # bulk.rotate (BulkRotateSecrets)
//
// POST /api/v1/projects/{id}/secrets/bulk-rotate:
//
//	Router gate: RequireScopedPermission(permSecretsWrite, projectScope)
//	Core gate:   requireActorActive only — BulkRotateSecrets takes the acting
//	             user ID and refuses a suspended or deactivated account, but
//	             does not check secrets.write (the router does). After that it
//	             checks s.AutoRotate and calls RotateSecretOnDemand per secret.
//	Model:       secrets.write @ project.
//	core:        errNotAuthzLayer for every active principal and for machines
//	             (core is not the permission layer); for a suspended principal
//	             the call must be refused (ErrPermissionDenied) — if core lets
//	             it through the leg reports Allowed, which the suspended-actor
//	             guard (TestCoreRefusesSuspendedActor) fails.
//	restOK:      pp.secretID appears in the "triggered" list.
//
// What this oracle does NOT verify:
//   - Per-item business rejections (AutoRotate=false → "no rotation config").
//   - Rotation-backend external calls (backend="" in the fixture → in-process only).
//   - Partial failures or audit-trail correctness.
//
// # mfa.stepup (VerifyMFAStepUp)
//
// POST /api/v1/auth/mfa/stepup:
//
//	Route:    r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/stepup", ...)
//	No RBAC gate: any authenticated user may call it.
//	Core:     VerifyMFAStepUp checks user.MFAEnabled — "not enabled" for un-enrolled users.
//	Model:    mfaRequired: true — only principals with mfa_enabled=true in the DB pass.
//	core_refusal: "none" (matrix.json) → coreEnforced=false → core leg excluded from Oracle 1.
//	REST:     blockWhenImpersonating + handler → VerifyMFAStepUp.
//	No gRPC surface (ADR-105 partial surface; /auth endpoints have no gRPC equivalent).
//
// Fixture: pkMFAUser is the only principal with MFA enrolled (world_test.go V5EXT4 seed).
// controlAs: pkMFAUser is the positive control (admin does NOT have MFA enrolled).
//
// TOTP code: computed fresh for each leg from fx.mfaUserTOTPSecret. Each leg has its
// own fresh DB copy (template clone), so the anti-replay mark (MarkTOTPStepUsed / LastUsedStep)
// does NOT carry over between the core and REST legs of the same case — they are independent.
//
// What this oracle does NOT verify:
//   - Recovery-code path (the fixture uses TOTP only).
//   - Lockout behaviour (too few invalid-code attempts to trigger).
//   - MFA-gated secret reads (the step-up grant enabling restricted secret access).
//   - Code correctness (whether the generated code is accepted depends on clock agreement).
func v5ext4Ops() []opSpec {
	return append(bulkRotateOps(), mfaStepUpOps()...)
}

// ---- bulk.rotate ----

func bulkRotateOps() []opSpec {
	return []opSpec{
		{
			name: "bulk.rotate", row: "BulkRotateSecrets", targets: projTargets,
			req: atP("secrets.write"),
			restOK: func(b []byte, fx *fixtures, t tgt) bool {
				return jsonListHas(b, "triggered", fx.proj(byte(t)).secretID)
			},
			// Core checks only that the actor is active; secrets.write is enforced at
			// the router. So the leg is a participant only for a principal core must
			// refuse (a suspended account): refused -> Denied, let through -> Allowed.
			// An active principal, permitted or not, is errNotAuthzLayer.
			core: func(ctx context.Context, lg *leg, p *principal, t tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				pp := lg.fx.proj(byte(t))
				_, err := lg.c.BulkRotateSecrets(ctx, p.userID, core.BulkRotateRequest{
					ProjectID: pp.projectID,
					SecretIDs: []uint{pp.secretID},
					RotatedBy: p.username,
				})
				if err != nil {
					return err
				}
				if !p.suspended {
					return errNotAuthzLayer
				}
				return nil
			},
			rest: func(fx *fixtures, t tgt, _ byte) restReq {
				pp := fx.proj(byte(t))
				return restReq{http.MethodPost,
					fmt.Sprintf("/api/v1/projects/%d/secrets/bulk-rotate", pp.projectID),
					map[string]any{"secret_ids": []uint{pp.secretID}}}
			},
		},
	}
}

// ---- mfa.stepup ----

// currentTOTPCode returns the current 6-digit TOTP code for secret. Called at
// the moment each leg runs so the code is within the current 30s window.
func currentTOTPCode(secret string) string {
	code, _ := totp.GenerateCode(secret, time.Now())
	return code
}

func mfaStepUpOps() []opSpec {
	return []opSpec{
		{
			name:    "mfa.stepup",
			row:     "VerifyMFAStepUp",
			targets: []tgt{tA}, // self-service, no project target; tA is the canonical single-target
			// controlAs: admin does not have MFA enrolled in the fixture; pkMFAUser does.
			controlAs: []principalKind{pkMFAUser},
			req: func(fx *fixtures, _ tgt, _ byte) requirement {
				return requirement{mfaRequired: true}
			},
			// coreEnforced=false (core_refusal="none" in matrix.json) → excluded from Oracle 1.
			// We still run the core leg to record it.
			core: func(ctx context.Context, lg *leg, p *principal, _ tgt, _ byte) error {
				if p.isMachine() {
					return errNotAuthzLayer
				}
				if p.systemActor {
					return errNotAuthzLayer
				}
				code := currentTOTPCode(lg.fx.mfaUserTOTPSecret)
				return lg.c.VerifyMFAStepUp(ctx, p.userID, code)
			},
			rest: func(fx *fixtures, _ tgt, _ byte) restReq {
				code := currentTOTPCode(fx.mfaUserTOTPSecret)
				return restReq{http.MethodPost, "/api/v1/auth/mfa/stepup",
					map[string]any{"code": code}}
			},
		},
	}
}

// isV5ext4Op reports whether name is one of the V5EXT4 bindings.
func isV5ext4Op(name string) bool {
	for _, s := range v5ext4Ops() {
		if s.name == name {
			return true
		}
	}
	return false
}
