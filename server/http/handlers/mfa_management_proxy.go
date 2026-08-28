// mfa_management_proxy.go — server-side endpoints backing RemoteStorage's MFA
// enrolment/management storage primitives (finding #524): GetMFASecret/
// CountUnusedMFARecoveryCodes/MarkTOTPStepUsed. (UpsertMFASecretProxy was
// deleted — G80 liveness sweep found no live caller; see
// docs/g80-remediation-notes.md.)
//
// ActivateMFASecretProxy/DeleteMFAForUserProxy/SetUserMFAEnabledProxy/
// CreateMFARecoveryCodesProxy/DeleteMFARecoveryCodesProxy were DELETED
// (#1593, docs/adr-089-mfa-purge-relay-deletion.md): the WithTransaction
// tx.X() blind-spot fix (ADR-088) made these five raw storage calls visible
// as bypassing internal/core.mfa.go's requireReauth step-up gate for the
// first time, but a liveness check found no caller could ever legitimately
// reach them — the server-side path (/auth/mfa/activate, /auth/mfa/disable)
// cannot run against RemoteStorage at all (validateRemoteStorageNotServer,
// internal/config/config.go, rejects storage.type: remote for ANY server
// process unconditionally), and the CLI (the only process that CAN
// construct a RemoteStorage-backed core) has no MFA command. See the ADR
// for why this is a deletion, not a fix, and what reviving these five would
// require.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// terminates every /auth/mfa/* request itself — BeginMFAEnrollment/ActivateMFA/
// DisableMFA/RegenerateMFARecoveryCodes/MFARecoveryCodesRemaining
// (internal/core/mfa.go) — it just needs somewhere to persist the TOTP secret
// and recovery-code rows. These routes (registered in server/http/router.go
// under /api/v1/system/mfa, gated on the existing system.read/system.write
// RBAC permissions — the SAME tier a RemoteStorage credential already needs
// for every other proxied call) mirror webauthn_proxy.go/sso_state_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/mfa.go already uses against a local backend — NO MFA POLICY
// decision is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// Sensitive-data boundary: SecretEnc/SecretMeta arrive and leave as opaque
// ciphertext, encrypted/decrypted only by the CALLING server's own
// internal/core.KeyorixCore.encryptAuthSecret/decryptAuthSecret — this file
// never touches plaintext. See remote_mfa.go's package doc for the full
// investigated reasoning (mirrors remote_dynamic.go's AdminDSN/Credential
// boundary exactly).
//
// Response envelope: like every other proxy in this package, these do NOT use
// the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mfaSecretProxyWire mirrors models.MFASecret's fields exactly (snake_case)
// and mfaSecretWire in internal/storage/store/remote_mfa.go. SecretEnc/
// SecretMeta/LastUsedStep are tagged json:"-" on the model (to keep them out
// of USER-facing responses) — irrelevant here, since this is an internal
// system-to-system wire format gated on system.read/system.write, matching
// webAuthnSessionProxyWire's identical json:"-"-field precedent.
type mfaSecretProxyWire struct {
	ID           uint      `json:"id"`
	UserID       uint      `json:"user_id"`
	SecretEnc    []byte    `json:"secret_enc"`
	SecretMeta   []byte    `json:"secret_meta"`
	Activated    bool      `json:"activated"`
	LastUsedStep *int64    `json:"last_used_step"`
	CreatedAt    time.Time `json:"created_at"`
}

func newMFASecretProxyWire(s *models.MFASecret) mfaSecretProxyWire {
	return mfaSecretProxyWire{
		ID:           s.ID,
		UserID:       s.UserID,
		SecretEnc:    s.SecretEnc,
		SecretMeta:   s.SecretMeta,
		Activated:    s.Activated,
		LastUsedStep: s.LastUsedStep,
		CreatedAt:    s.CreatedAt,
	}
}

func parseMFAUserIDQuery(w http.ResponseWriter, r *http.Request) (userID uint, ok bool) {
	v := r.URL.Query().Get("user_id")
	if v == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_id query parameter is required")
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_id must be a valid integer")
		return 0, false
	}
	return uint(id), true
}

// GetMFASecretProxy handles GET /api/v1/system/mfa/secrets?user_id=X.
func (h *AuthHandler) GetMFASecretProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDQuery(w, r)
	if !ok {
		return
	}
	s, err := h.coreService.Storage().GetMFASecret(r.Context(), userID)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "MFA secret not found")
			return
		}
		log.Printf("mfa proxy: get secret failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMFASecretProxyWire(s))
}

// CountUnusedMFARecoveryCodesProxy handles GET
// /api/v1/system/mfa/recovery-codes/count?user_id=X.
func (h *AuthHandler) CountUnusedMFARecoveryCodesProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDQuery(w, r)
	if !ok {
		return
	}
	n, err := h.coreService.Storage().CountUnusedMFARecoveryCodes(r.Context(), userID)
	if err != nil {
		log.Printf("mfa proxy: count recovery codes failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int{"count": n})
}

// markTOTPStepUsedWire is the request body for MarkTOTPStepUsedProxy.
type markTOTPStepUsedWire struct {
	UserID uint  `json:"user_id"`
	Step   int64 `json:"step"`
}

// MarkTOTPStepUsedProxy handles POST /api/v1/system/mfa/totp-step-used.
// Atomically advances the per-user last-used TOTP step so the downstream
// core's requireReauth/VerifyMFACredentials anti-replay guard works correctly
// under storage.type: remote (finding in PR that follows #524).
func (h *AuthHandler) MarkTOTPStepUsedProxy(w http.ResponseWriter, r *http.Request) {
	var body markTOTPStepUsedWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id is required")
		return
	}
	fresh, err := h.coreService.Storage().MarkTOTPStepUsed(r.Context(), body.UserID, body.Step)
	if err != nil {
		log.Printf("mfa proxy: mark TOTP step used failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"fresh": fresh})
}
