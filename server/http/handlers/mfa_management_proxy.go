// mfa_management_proxy.go — server-side endpoints backing RemoteStorage's MFA
// enrolment/management storage primitives (finding #524):
// GetMFASecret/ActivateMFASecret/DeleteMFAForUser/
// SetUserMFAEnabled/CreateMFARecoveryCodes/CountUnusedMFARecoveryCodes/
// DeleteMFARecoveryCodes. (UpsertMFASecretProxy was deleted — G80 liveness
// sweep found no live caller; see docs/g80-remediation-notes.md.)
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// terminates every /auth/mfa/* request itself — BeginMFAEnrollment/ActivateMFA/
// DisableMFA/RegenerateMFARecoveryCodes/MFARecoveryCodesRemaining
// (internal/core/mfa.go) — it just needs somewhere to persist the TOTP secret
// and recovery-code rows. Before this fix none of these eight storage methods
// had a server route to call at all, so MFA enrolment and management (though
// NOT already-active MFA login, which is proxied separately via
// RemoteMFAVerifier — see remote_mfa.go's package doc) were 100% broken under
// storage.type: remote. These routes (registered in server/http/router.go
// under /api/v1/system/mfa, gated on the existing system.read/system.write
// RBAC permissions — the SAME tier a RemoteStorage credential already needs
// for every other proxied call) mirror webauthn_proxy.go/sso_state_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/mfa.go already uses against a local backend — NO MFA POLICY
// decision (the re-auth gate before activate/disable/regenerate, the
// single-active-method enforcement, recovery-code generation/hashing, or the
// post-activation session invalidation) is made here; that stays entirely in
// the CALLING server's own internal/core.KeyorixCore, exactly as it does
// against a local backend.
//
// Sensitive-data boundary: SecretEnc/SecretMeta arrive and leave as opaque
// ciphertext, encrypted/decrypted only by the CALLING server's own
// internal/core.KeyorixCore.encryptAuthSecret/decryptAuthSecret — this file
// never touches plaintext. See remote_mfa.go's package doc for the full
// investigated reasoning (mirrors remote_dynamic.go's AdminDSN/Credential
// boundary exactly).
//
// Atomicity: every handler below calls exactly ONE storage.Storage method, so
// each preserves whatever transactional guarantee local_mfa.go's own
// implementation already has (DeleteMFAForUserProxy's DELETE inherits
// local_mfa.go's internal secret+recovery-codes GORM transaction unchanged;
// every other handler is a single unconditional UPDATE/INSERT/DELETE/SELECT,
// matching the local backend's own semantics exactly) — see remote_mfa.go's
// package doc for the full analysis of why no NEW combined atomic primitive
// (unlike AdvanceWebAuthnCredentialCounterProxy/
// CreateSecretDependencyExclusiveProxy) is needed here.
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

	"github.com/go-chi/chi/v5"
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

func parseMFAUserIDParam(w http.ResponseWriter, r *http.Request, name string) (userID uint, ok bool) {
	id, err := strconv.ParseUint(chi.URLParam(r, name), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
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

// ActivateMFASecretProxy handles POST
// /api/v1/system/mfa/secrets/{userId}/activate.
func (h *AuthHandler) ActivateMFASecretProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDParam(w, r, "userId")
	if !ok {
		return
	}
	if err := h.coreService.Storage().ActivateMFASecret(r.Context(), userID); err != nil {
		log.Printf("mfa proxy: activate secret failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"activated": true})
}

// DeleteMFAForUserProxy handles DELETE /api/v1/system/mfa/users/{userId}. Calls
// storage.Storage.DeleteMFAForUser directly, so this inherits local_mfa.go's
// own secret+recovery-codes GORM transaction unchanged.
func (h *AuthHandler) DeleteMFAForUserProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDParam(w, r, "userId")
	if !ok {
		return
	}
	if err := h.coreService.Storage().DeleteMFAForUser(r.Context(), userID); err != nil {
		log.Printf("mfa proxy: delete for user failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// setUserMFAEnabledProxyBody is the wire body for SetUserMFAEnabledProxy.
type setUserMFAEnabledProxyBody struct {
	Enabled bool `json:"enabled"`
}

// SetUserMFAEnabledProxy handles PUT
// /api/v1/system/mfa/users/{userId}/mfa-enabled.
func (h *AuthHandler) SetUserMFAEnabledProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDParam(w, r, "userId")
	if !ok {
		return
	}
	var body setUserMFAEnabledProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if err := h.coreService.Storage().SetUserMFAEnabled(r.Context(), userID, body.Enabled); err != nil {
		log.Printf("mfa proxy: set mfa enabled failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// createMFARecoveryCodesProxyBody is the wire body for
// CreateMFARecoveryCodesProxy.
type createMFARecoveryCodesProxyBody struct {
	CodeHashes []string `json:"code_hashes"`
}

// CreateMFARecoveryCodesProxy handles POST
// /api/v1/system/mfa/recovery-codes?user_id=X. Only the SHA-256 hashes ever
// cross the wire — the caller (ActivateMFA/RegenerateMFARecoveryCodes,
// internal/core/mfa.go) generates and hashes the plaintext codes itself,
// exactly as it does against a local backend.
func (h *AuthHandler) CreateMFARecoveryCodesProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDQuery(w, r)
	if !ok {
		return
	}
	var body createMFARecoveryCodesProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if err := h.coreService.Storage().CreateMFARecoveryCodes(r.Context(), userID, body.CodeHashes); err != nil {
		log.Printf("mfa proxy: create recovery codes failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"created": true})
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

// DeleteMFARecoveryCodesProxy handles DELETE
// /api/v1/system/mfa/recovery-codes/{userId}.
func (h *AuthHandler) DeleteMFARecoveryCodesProxy(w http.ResponseWriter, r *http.Request) {
	userID, ok := parseMFAUserIDParam(w, r, "userId")
	if !ok {
		return
	}
	if err := h.coreService.Storage().DeleteMFARecoveryCodes(r.Context(), userID); err != nil {
		log.Printf("mfa proxy: delete recovery codes failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}
