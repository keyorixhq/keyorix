// webauthn.go — HTTP handlers for WebAuthn / passkeys (ADR-036): self-service
// registration (authenticated) of FIDO2 authenticators, listing/removing them,
// and the public two-step login assertion ceremony. The ceremony state is carried
// between begin and finish by an opaque webauthn_session token (hashed at rest).
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/keyorixhq/keyorix/internal/core"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// maxWebAuthnBody caps the ceremony request body (attestation/assertion blobs are
// small; this bounds parsing of untrusted input).
const maxWebAuthnBody = 64 * 1024

// BeginWebAuthnRegistration starts passkey enrolment for the authenticated caller.
func (h *AuthHandler) BeginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	creation, sessionToken, err := h.coreService.BeginWebAuthnRegistration(r.Context(), userCtx.UserID)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        creation.Response,
		"webauthn_session": sessionToken,
	}, "Create a passkey, then finish registration.")
}

// FinishWebAuthnRegistration verifies the attestation and stores the passkey.
// Body: { webauthn_session, name, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	var body struct {
		WebAuthnSession string          `json:"webauthn_session"`
		Name            string          `json:"name"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid attestation", http.StatusBadRequest, nil)
		return
	}
	cred, err := h.coreService.FinishWebAuthnRegistration(r.Context(), userCtx.UserID, body.WebAuthnSession, strings.TrimSpace(body.Name), parsed)
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"id":         cred.ID,
		"name":       cred.Name,
		"created_at": cred.CreatedAt,
	}, "Passkey registered.")
}

// ListWebAuthnCredentials returns the caller's registered passkeys.
func (h *AuthHandler) ListWebAuthnCredentials(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	creds, err := h.coreService.ListWebAuthnCredentials(r.Context(), userCtx.UserID)
	if err != nil {
		sendError(w, "InternalError", "Failed to list passkeys", http.StatusInternalServerError, nil)
		return
	}
	out := make([]map[string]interface{}, 0, len(creds))
	for _, c := range creds {
		out = append(out, map[string]interface{}{
			"id":           c.ID,
			"name":         c.Name,
			"created_at":   c.CreatedAt,
			"last_used_at": c.LastUsedAt,
		})
	}
	sendSuccess(w, out, "")
}

// DeleteWebAuthnCredential removes one of the caller's passkeys.
func (h *AuthHandler) DeleteWebAuthnCredential(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid credential id", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteWebAuthnCredential(r.Context(), userCtx.UserID, uint(id)); err != nil {
		sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
		return
	}
	sendSuccess(w, map[string]interface{}{"id": id, "deleted": true}, "Passkey removed.")
}

// BeginWebAuthnLogin starts the assertion ceremony for the second login step.
// Body: { mfa_challenge }. Public (the challenge from /auth/login is the bearer).
func (h *AuthHandler) BeginWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge string `json:"mfa_challenge"`
	}
	if err := decodeJSON(r, &body); err != nil {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	assertion, sessionToken, err := h.coreService.BeginWebAuthnLogin(r.Context(), body.Challenge)
	if err != nil {
		h.recordLoginAttempt(r.Context(), ip)
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        assertion.Response,
		"webauthn_session": sessionToken,
	}, "Complete the passkey assertion.")
}

// FinishWebAuthnLogin verifies the assertion and returns a session.
// Body: { mfa_challenge, webauthn_session, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		Challenge       string          `json:"mfa_challenge"`
		WebAuthnSession string          `json:"webauthn_session"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid assertion", http.StatusBadRequest, nil)
		return
	}
	session, user, err := h.coreService.FinishWebAuthnLogin(r.Context(), body.Challenge, body.WebAuthnSession, r.Header.Get("User-Agent"), ip, parsed)
	if err != nil {
		h.recordLoginAttempt(r.Context(), ip)
		sendError(w, "Unauthorized", "Assertion failed or challenge expired", http.StatusUnauthorized, nil)
		return
	}
	resp := h.buildLoginResponse(r.Context(), session, user)
	go h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get("User-Agent")) // #nosec G118
	go func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }()                                // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// BeginWebAuthnPasswordlessLogin starts a usernameless passkey login. Public, no
// body — the authenticator reveals which resident passkey/user to use.
func (h *AuthHandler) BeginWebAuthnPasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	assertion, sessionToken, err := h.coreService.BeginWebAuthnPasswordlessLogin(r.Context())
	if err != nil {
		h.writeWebAuthnErr(w, err)
		return
	}
	sendSuccess(w, map[string]interface{}{
		"publicKey":        assertion.Response,
		"webauthn_session": sessionToken,
	}, "Complete the passkey assertion to sign in.")
}

// FinishWebAuthnPasswordlessLogin verifies a discoverable assertion and returns a
// session. Body: { webauthn_session, credential: <PublicKeyCredential> }.
func (h *AuthHandler) FinishWebAuthnPasswordlessLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if h.checkLoginRateLimit(r.Context(), ip) {
		sendError(w, "TooManyRequests", "Too many attempts. Try again later.", http.StatusTooManyRequests, nil)
		return
	}
	var body struct {
		WebAuthnSession string          `json:"webauthn_session"`
		Credential      json.RawMessage `json:"credential"`
	}
	if err := decodeJSON(r, &body); err != nil || len(body.Credential) == 0 {
		sendError(w, "BadRequest", "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body.Credential)
	if err != nil {
		sendError(w, "BadRequest", "Invalid assertion", http.StatusBadRequest, nil)
		return
	}
	session, user, err := h.coreService.FinishWebAuthnPasswordlessLogin(r.Context(), body.WebAuthnSession, r.Header.Get("User-Agent"), ip, parsed)
	if err != nil {
		h.recordLoginAttempt(r.Context(), ip)
		sendError(w, "Unauthorized", "Passwordless login failed", http.StatusUnauthorized, nil)
		return
	}
	resp := h.buildLoginResponse(r.Context(), session, user)
	go h.coreService.LogAuthLogin(context.Background(), user.ID, user.Username, ip, r.Header.Get("User-Agent")) // #nosec G118
	go func() { _ = h.coreService.RecordLogin(context.Background(), user.ID) }()                                // #nosec G118
	sendSuccess(w, resp, "Login successful")
}

// writeWebAuthnErr maps a core error to an HTTP status: disabled → 501, else 400.
func (h *AuthHandler) writeWebAuthnErr(w http.ResponseWriter, err error) {
	if errors.Is(err, core.ErrWebAuthnDisabled) {
		sendError(w, "NotImplemented", err.Error(), http.StatusNotImplemented, nil)
		return
	}
	sendError(w, "Error", err.Error(), http.StatusBadRequest, nil)
}

// decodeJSON decodes a size-capped JSON request body.
func decodeJSON(r *http.Request, v interface{}) error {
	return json.NewDecoder(io.LimitReader(r.Body, maxWebAuthnBody)).Decode(v)
}
