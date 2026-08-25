// users_credentials_proxy.go — server-side endpoints backing RemoteStorage's
// RevokeAllPersonalAccessTokensForUser/DeleteSessionsForUserExcept storage
// primitives (G80 residual: the UpdateUserIfActiveStateMatchesProxy
// "PAT/session revocation half," server/http/raw_storage_bypass_guard_test.go's
// knownUnfixedRawStorageBypasses entry for that handler).
//
// These routes are registered in server/http/router.go under
// /api/v1/system/users/{id}/..., inside the /system route group. Unlike most
// other proxies in this package, these do NOT rely on the group's blanket
// system.write gate alone: core.UpdateUser/core.DeleteUser perform no
// caller-authority check of their own on a deactivating transition (only
// guardLastAdminDeactivation, a target-state invariant with no actor
// parameter) — the actual ceiling that governs "who may deactivate a user"
// lives entirely at the HTTP layer, on RequirePermission(permUsersWrite) at
// PUT /api/v1/users/{id} (server/http/router.go). Revoking a user's live
// PATs/sessions is a sub-operation of that same action (core.UpdateUser's own
// deactivating branch already does both under a real local transaction), so
// it must inherit that SAME ceiling, not the broader, differently-scoped
// system.write these routes also sit behind — see
// internal/core/users.go's requireUserCredentialsRevokeAuthority doc for the
// full derivation. This check now runs unconditionally for every caller. It
// used to be skipped for a genuine node-credential relay (mirroring what
// CreateOIDCBindingProxy/DeleteOIDCBindingProxy/
// CreateMachineIdentityCredentialProxy did before ADR-085) — ADR-085
// (Accepted, 2026-08-25) found that "downstream node relay" topology cannot
// exist in this codebase (ADR-083's validateRemoteStorageNotServer rejects
// storage.type: remote for any server process) and removed the exemption.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/server/middleware"
)

// deleteSessionsForUserExceptProxyBody mirrors RemoteStorage's
// deleteSessionsForUserExceptWire (internal/storage/store/remote_auth.go).
type deleteSessionsForUserExceptProxyBody struct {
	ExceptSessionID uint `json:"except_session_id"`
}

// requestActorKindAndID resolves the (actorType, actorID) pair
// AuthorizePrincipal needs from the request context, defaulting to a
// zero-value human actor (denied by AuthorizePrincipal, same as every other
// unauthenticated-relative-to-RBAC caller in this package) when no context is
// present at all.
func requestActorKindAndID(r *http.Request) (string, uint) {
	u := middleware.GetUserFromContext(r.Context())
	if u == nil {
		return "user", 0
	}
	return u.ActorKind(), u.PrincipalID()
}

// writeUserCredentialsRevokeError maps requireUserCredentialsRevokeAuthority's
// denial (a distinctive "users.write authority" substring, mirroring
// CreateOIDCBindingProxy's own "admin authority is required" substring check)
// to 403; anything else is a genuine storage/resolution failure, 500.
func writeUserCredentialsRevokeError(w http.ResponseWriter, op string, err error) {
	if strings.Contains(err.Error(), "users.write authority") {
		writeRemoteAPIError(w, http.StatusForbidden, "PERMISSION_DENIED", clientSafe(err))
		return
	}
	log.Printf("users-credentials proxy: %s failed: %v", op, err)
	writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
}

// RevokeAllPersonalAccessTokensForUserProxy handles POST
// /api/v1/system/users/{id}/personal-access-tokens/revoke-all.
func (h *UserHandler) RevokeAllPersonalAccessTokensForUserProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	actorType, actorID := requestActorKindAndID(r)
	hashes, err := h.coreService.RevokeAllPersonalAccessTokensForUser(r.Context(), actorType, actorID, uint(id))
	if err != nil {
		writeUserCredentialsRevokeError(w, "revoke-all-pats", err)
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"hashes": hashes})
}

// DeleteSessionsForUserExceptProxy handles POST
// /api/v1/system/users/{id}/sessions/delete-except.
func (h *UserHandler) DeleteSessionsForUserExceptProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	var body deleteSessionsForUserExceptProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	actorType, actorID := requestActorKindAndID(r)
	if err := h.coreService.DeleteSessionsForUserExcept(r.Context(), actorType, actorID, uint(id), body.ExceptSessionID); err != nil {
		writeUserCredentialsRevokeError(w, "delete-sessions-except", err)
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}
