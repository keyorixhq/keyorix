package faultops

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// MFA-RESET-TESTS-1 item 3: the three MFA reset ops of the two-administrator flow
// (RECOVERY-MFA-RESET-1, #3751), which inventory_overrides_test.go left
// StatusPending. Appended in their own file, after zz_scim_ops_catalog_test.go: Go
// runs init()s in file-name order and fuzz seeds address ops by opCatalog INDEX, so
// appending keeps every committed seed on the op it was recorded against.
//
// The oracle that matters for them is mfa_reset_oracle_test.go's: after any fault,
// a target whose second factor is gone must not still have a working old password
// or a live session / personal access token.

const (
	mfaResetFuzzAdminB = "fuzz-mfa-reset-admin-b"
	mfaResetFuzzTarget = "fuzz-mfa-reset-target"
)

// mfaResetFuzzState is what Setup hands to Execute.
type mfaResetFuzzState struct {
	adminSecret  string // the bootstrapped admin's (requester's) TOTP secret
	adminBToken  string // the second administrator's bearer token
	adminBSecret string
	targetID     uint
	requestID    uint // 0 for the request op itself
}

// enrolUserMFADirect gives userID an activated TOTP factor, ten recovery codes and
// (withPasskey) one WebAuthn credential, written the way enrolMFADirect does: the
// secret goes through the real BeginMFAEnrollment (so it is genuinely encrypted) and
// the activation is flipped in storage, leaving TOTP step 0 unspent for Execute.
func enrolUserMFADirect(ctx context.Context, w *faultWorld, userID uint, withPasskey bool) (string, error) {
	_, secret, err := w.core.BeginMFAEnrollment(ctx, userID)
	if err != nil {
		return "", fmt.Errorf("BeginMFAEnrollment(%d): %w", userID, err)
	}
	if err := w.db.Model(&models.MFASecret{}).Where("user_id = ?", userID).Update("activated", true).Error; err != nil {
		return "", fmt.Errorf("activating mfa_secrets row: %w", err)
	}
	updates := map[string]any{"mfa_enabled": true}
	if withPasskey {
		updates["web_authn_enabled"] = true
	}
	if err := w.db.Model(&models.User{}).Where("id = ?", userID).Updates(updates).Error; err != nil {
		return "", fmt.Errorf("enabling MFA flags: %w", err)
	}
	codes := make([]*models.MFARecoveryCode, 0, 10)
	for i := range 10 {
		codes = append(codes, &models.MFARecoveryCode{UserID: userID, CodeHash: fmt.Sprintf("faultops-seeded-recovery-code-hash-%02d", i)})
	}
	if err := w.db.Create(&codes).Error; err != nil {
		return "", fmt.Errorf("seeding recovery codes: %w", err)
	}
	if withPasskey {
		cred := &models.WebAuthnCredential{UserID: userID, CredentialID: fmt.Appendf(nil, "faultops-cred-%d", userID), Name: "fuzz key", CredentialBlob: []byte("{}")}
		if err := w.db.Create(cred).Error; err != nil {
			return "", fmt.Errorf("seeding webauthn credential: %w", err)
		}
	}
	return secret, nil
}

func setupMFAResetWorld(ctx context.Context, w *faultWorld, openRequest bool) (*mfaResetFuzzState, error) {
	if err := w.ensureEncryption(); err != nil {
		return nil, fmt.Errorf("ensureEncryption: %w", err)
	}
	adminSecret, err := enrolMFADirect(ctx, w)
	if err != nil {
		return nil, err
	}
	adminID, err := faultAdminUserID(w)
	if err != nil {
		return nil, err
	}
	// The second administrator: a global admin with TOTP, logged in BEFORE its
	// factor is switched on (a login with MFA enabled needs a challenge round trip).
	bID, err := createUserForFuzz(ctx, w, mfaResetFuzzAdminB)
	if err != nil {
		return nil, err
	}
	roleIDs, err := w.core.Storage().GetUserRoleIDsAt(ctx, adminID, coreStorage.Scope{})
	if err != nil || len(roleIDs) == 0 {
		return nil, fmt.Errorf("admin role of the bootstrapped admin: %v (%d roles)", err, len(roleIDs))
	}
	if err := w.core.Storage().AssignRole(ctx, bID, roleIDs[0], coreStorage.Scope{}); err != nil {
		return nil, fmt.Errorf("AssignRole(admin-b): %w", err)
	}
	bToken, err := loginForFuzz(ctx, w, mfaResetFuzzAdminB, fuzzUserPassword)
	if err != nil {
		return nil, err
	}
	bSecret, err := enrolUserMFADirect(ctx, w, bID, false)
	if err != nil {
		return nil, err
	}
	// The target: TOTP, recovery codes, a passkey, a session and a PAT the reset must kill.
	targetID, err := createUserForFuzz(ctx, w, mfaResetFuzzTarget)
	if err != nil {
		return nil, err
	}
	if _, err := enrolUserMFADirect(ctx, w, targetID, true); err != nil {
		return nil, err
	}
	exp := time.Now().Add(time.Hour)
	if err := w.db.Create(&models.Session{UserID: targetID, SessionToken: "faultops-mfa-reset-target-session", CreatedAt: time.Now(), ExpiresAt: &exp}).Error; err != nil {
		return nil, fmt.Errorf("seeding target session: %w", err)
	}
	if err := w.db.Create(&models.PersonalAccessToken{UserID: targetID, Name: "ci", TokenHash: "faultops-mfa-reset-target-pat"}).Error; err != nil {
		return nil, fmt.Errorf("seeding target PAT: %w", err)
	}
	st := &mfaResetFuzzState{adminSecret: adminSecret.(string), adminBToken: bToken, adminBSecret: bSecret, targetID: targetID}
	if openRequest {
		// Through the core, not HTTP: the requester's TOTP step is spent here, which
		// is fine for the approve and cancel ops (different admin / no step-up).
		code, err := totp.GenerateCode(st.adminSecret, time.Now())
		if err != nil {
			return nil, err
		}
		req, err := w.core.RequestMFAReset(ctx, adminID, false, core.MFAResetRequestInput{
			User: mfaResetFuzzTarget, Reason: "lost phone", VerifiedBy: "video", Evidence: "fuzz", Code: code,
		})
		if err != nil {
			return nil, fmt.Errorf("setup RequestMFAReset: %w", err)
		}
		st.requestID = req.ID
	}
	return st, nil
}

func init() {
	opCatalog = append(opCatalog,
		operation{
			Key: "REST POST /api/v1/mfa-reset-requests",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return setupMFAResetWorld(ctx, w, false)
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				s := state.(*mfaResetFuzzState)
				code, err := totp.GenerateCode(s.adminSecret, time.Now())
				if err != nil {
					return opResult{}, err
				}
				st, body, err := httpJSON(ctx, w, http.MethodPost, "/api/v1/mfa-reset-requests", map[string]any{
					"user": mfaResetFuzzTarget, "reason": "lost phone", "verified_by": "video", "evidence": "fuzz", "code": code,
				})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
		operation{
			// The op the oracle is about: B approves A's request, which clears the
			// target's factors, replaces its password and revokes its sessions and PATs.
			Key: "REST POST /api/v1/mfa-reset-requests/{id}/approve",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return setupMFAResetWorld(ctx, w, true)
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				s := state.(*mfaResetFuzzState)
				code, err := totp.GenerateCode(s.adminBSecret, time.Now())
				if err != nil {
					return opResult{}, err
				}
				st, body, err := httpJSONAs(ctx, w, s.adminBToken, http.MethodPost,
					fmt.Sprintf("/api/v1/mfa-reset-requests/%d/approve", s.requestID), map[string]any{"code": code})
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
		operation{
			Key: "REST POST /api/v1/mfa-reset-requests/{id}/cancel",
			Setup: func(ctx context.Context, w *faultWorld) (any, error) {
				return setupMFAResetWorld(ctx, w, true)
			},
			Execute: func(ctx context.Context, w *faultWorld, state any) (opResult, error) {
				s := state.(*mfaResetFuzzState)
				st, body, err := httpJSON(ctx, w, http.MethodPost, fmt.Sprintf("/api/v1/mfa-reset-requests/%d/cancel", s.requestID), nil)
				if err != nil {
					return opResult{}, err
				}
				return httpResult(st, body), nil
			},
		},
	)
}
