// sessions_remote.go — server-side counterparts of RemoteStorage's session
// lookup/deletion (#508): GET /api/v1/sessions/{token} and
// DELETE /api/v1/sessions/{id}.
//
// Deliberately NOT a POST /api/v1/sessions "create session" route — see
// internal/storage/store/remote_auth.go's CreateSession doc for why a
// generic mint-any-session wire primitive is unsafe. Session issuance under
// storage.type: remote happens atomically with credential verification via
// POST /api/v1/users/verify-credentials (users_crud.go's VerifyCredentials)
// instead. These two routes only ever LOOK UP or DELETE a session that
// already exists — a lookup requires presenting that exact session's own
// opaque token (proof of possession, not a credential check bypass), and a
// delete-by-ID grants no capability beyond what RevokeUserSessions
// (POST /users/{id}/revoke-sessions) already grants the same service
// credential today.
package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// GetSessionByToken handles GET /api/v1/sessions/{token} (#508) — the
// server-side counterpart RemoteStorage.GetSession needs to validate a
// session under storage.type: remote (core.ValidateSessionToken, on every
// authenticated request via a spoke deployment) and to resolve a session's ID
// before deleting it (core.Logout). Gated by users.write, the same
// permission VerifyCredentials/CreateUser/UnlockUser already require of the
// RemoteStorage service credential.
func (h *UserHandler) GetSessionByToken(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	token := chi.URLParam(r, "token")
	if token == "" {
		sendError(w, "InvalidParameter", "session token is required", http.StatusBadRequest, nil)
		return
	}
	session, err := h.coreService.GetSessionForRemoteProxy(r.Context(), token)
	if err != nil {
		sendError(w, "NotFound", "Session not found", http.StatusNotFound, nil)
		return
	}
	// session.SessionToken is the at-rest HASH (never the plaintext — see
	// models.Session's json:"-" tag), so this response never carries a
	// replayable secret; it's plain lookup metadata (ID, user, expiry).
	sendSuccess(w, session, "")
}

// DeleteSessionByID handles DELETE /api/v1/sessions/{id} (#508) — the
// server-side counterpart RemoteStorage.DeleteSession needs so Logout works
// end-to-end under storage.type: remote. Gated by users.write, matching
// GetSessionByToken above.
func (h *UserHandler) DeleteSessionByID(w http.ResponseWriter, r *http.Request) {
	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		sendError(w, "Unauthorized", "User context not found", http.StatusUnauthorized, nil)
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		sendError(w, "InvalidParameter", "Invalid session ID", http.StatusBadRequest, nil)
		return
	}
	if err := h.coreService.DeleteSessionForRemoteProxy(r.Context(), uint(id)); err != nil {
		sendError(w, "InternalError", "Failed to delete session", http.StatusInternalServerError, nil)
		return
	}
	sendSuccess(w, nil, "")
}

// GetSessionByToken handles GET /api/v1/sessions/{token} (#508).
func GetSessionByToken(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", "User handler not initialised", http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.GetSessionByToken(w, r)
}

// DeleteSessionByID handles DELETE /api/v1/sessions/{id} (#508).
func DeleteSessionByID(w http.ResponseWriter, r *http.Request) {
	if defaultUserHandler == nil {
		sendError(w, "ServiceUnavailable", "User handler not initialised", http.StatusServiceUnavailable, nil)
		return
	}
	defaultUserHandler.DeleteSessionByID(w, r)
}
