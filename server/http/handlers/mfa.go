// mfa.go — HTTP handlers for TOTP MFA: self-service enrol/activate/disable
// (authenticated) and the public two-step login verify.
package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// EnrollMFA begins TOTP enrolment for the authenticated caller and returns the
// otpauth:// provisioning URI (for a QR code) plus the base32 secret.
func (h *AuthHandler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	uri, secret, err := h.coreService.BeginMFAEnrollment(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"otpauth_uri": uri,
		"secret":      secret,
	}, "Scan the QR code in your authenticator app, then activate with a code.")
}

// ActivateMFA confirms enrolment with a TOTP code and returns the one-time-shown
// recovery codes. Requires the account password to re-authenticate the caller
// (#372): code alone proves control of the just-generated pending secret, which an
// attacker with a stolen session or PAT could have generated themselves via
// EnrollMFA, so it is not proof this is really the account holder.
func (h *AuthHandler) ActivateMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	codes, err := h.coreService.ActivateMFA(r.Context(), userCtx.UserID, body.Code, body.Password)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"recovery_codes": codes,
	}, "MFA enabled. Save these recovery codes now — they will not be shown again.")
}

// DisableMFA turns off MFA after verifying a current code or the password.
func (h *AuthHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	if err := h.coreService.DisableMFA(r.Context(), userCtx.UserID, proof); err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{"mfa_enabled": false}, "MFA disabled")
}

// RegenerateRecoveryCodes issues a fresh set of recovery codes (replacing the old
// ones) after verifying a current TOTP code or the password. The codes are returned
// once and never shown again.
func (h *AuthHandler) RegenerateRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	codes, err := h.coreService.RegenerateMFARecoveryCodes(r.Context(), userCtx.UserID, proof)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"recovery_codes": codes,
	}, "New recovery codes generated. Save them now — they replace your old codes and will not be shown again.")
}

// RecoveryCodesStatus reports how many unused recovery codes remain (and the total),
// so the account UI can prompt a regenerate when the user is running low.
func (h *AuthHandler) RecoveryCodesStatus(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", errUserContext, http.StatusUnauthorized, nil)
		return
	}
	remaining, total, err := h.coreService.MFARecoveryCodesRemaining(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeMFAErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"remaining": remaining,
		"total":     total,
	}, "")
}

// VerifyMFA completes the two-step login: it consumes the challenge from
// /auth/login, verifies the TOTP (or recovery) code, and returns a session.
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge string `json:"mfa_challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", errInvalidRequestBody, http.StatusBadRequest, nil)
		return
	}
	session, user, err := h.coreService.VerifyMFALogin(r.Context(), body.Challenge, body.Code, r.Header.Get("User-Agent"), ip)
	if err != nil {
		h.recordLoginAttempt(r.Context(), ip)
		sendError(w, "Unauthorized", "Invalid or expired code", http.StatusUnauthorized, nil)
		return
	}
	resp := h.buildLoginResponse(r.Context(), session, user)
	h.setSessionCookies(w, session)
	goSafe(func() {
		h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get("User-Agent"))
	}) // #nosec G118
	goSafe(func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }) // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// mfaSafeMessages are the fixed, deliberately client-safe error strings core's
// MFA functions return for expected failure modes (missing user, already/not
// enrolled, bad code, lockout, etc.) — never wrapped around a lower-layer
// error, so passing them through as-is cannot leak driver/schema detail
// (backlog #116). The reauth-related entries mirror webauthnSafeMessages:
// both files' self-service flows call the same core.requireReauth function.
var mfaSafeMessages = map[string]bool{
	"user not found": true,
	"MFA enrolment requires at-rest encryption to be enabled (the TOTP secret must not be stored in plaintext); ask an administrator to enable encryption": true,
	"MFA is already enabled; disable it first to re-enrol": true,
	"no pending MFA enrolment; begin enrolment first":      true,
	"invalid code":             true,
	"MFA is not enabled":       true,
	"invalid code or password": true,
	"account temporarily locked due to repeated failed logins; try again later": true,
}

// writeMFAErr maps a core MFA error to a 400 response: a recognized safe
// message (mfaSafeMessages) is passed through as-is; anything else — including
// every error wrapping a lower-layer failure (e.g. "failed to store TOTP
// secret: %w") or a bare storage-layer error — is logged server-side and
// replaced with clientSafe()'s generic message before it reaches the client.
func (h *AuthHandler) writeMFAErr(w http.ResponseWriter, err error) {
	msg := err.Error()
	if !mfaSafeMessages[msg] {
		log.Printf("MFA error: %v", err)
		msg = clientSafe(err)
	}
	sendError(w, "Error", msg, http.StatusBadRequest, nil)
}
