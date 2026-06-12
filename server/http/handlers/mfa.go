// mfa.go — HTTP handlers for TOTP MFA: self-service enrol/activate/disable
// (authenticated) and the public two-step login verify.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// EnrollMFA begins TOTP enrolment for the authenticated caller and returns the
// otpauth:// provisioning URI (for a QR code) plus the base32 secret.
func (h *AuthHandler) EnrollMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	uri, secret, err := h.coreService.BeginMFAEnrollment(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"otpauth_uri": uri,
		"secret":      secret,
	}, "Scan the QR code in your authenticator app, then activate with a code.")
}

// ActivateMFA confirms enrolment with a TOTP code and returns the one-time-shown
// recovery codes.
func (h *AuthHandler) ActivateMFA(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	codes, err := h.coreService.ActivateMFA(r.Context(), userCtx.UserID, body.Code)
	if err != nil {
		sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
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
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	proof := body.Code
	if proof == "" {
		proof = body.Password
	}
	if err := h.coreService.DisableMFA(r.Context(), userCtx.UserID, proof); err != nil {
		sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"mfa_enabled": false}, "MFA disabled")
}

// VerifyMFA completes the two-step login: it consumes the challenge from
// /auth/login, verifies the TOTP (or recovery) code, and returns a session.
func (h *AuthHandler) VerifyMFA(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	if checkLoginRateLimit(ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge string `json:"mfa_challenge"`
		Code      string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	session, user, err := h.coreService.VerifyMFALogin(r.Context(), body.Challenge, body.Code, r.Header.Get("User-Agent"), ip)
	if err != nil {
		recordLoginAttempt(ip)
		sendError(w, "Unauthorized", "Invalid or expired code", http.StatusUnauthorized, nil)
		return
	}
	resp := h.buildLoginResponse(r.Context(), session, user)
	go h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get("User-Agent")) // #nosec G118
	go func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }()                                // #nosec G118
	sendSuccess(w, resp, "Login successful")
}
