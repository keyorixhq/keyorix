// users_active_transition_proxy.go — server-side endpoint backing
// RemoteStorage's UpdateUserIfActiveStateMatches (closing the UpdateUser
// IsActive TOCTOU race described in internal/core/storage/interface.go's
// UpdateUserIfActiveStateMatches doc, this codebase's user-row analogue of
// TransitionMachineIdentityState #388/#518 and UpdateProjectInvitation #412).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies this conditional write to whichever upstream server it's configured
// against, through this route (registered in server/http/router.go under
// /api/v1/system/users/{id}/active-transition, gated on the existing
// system.write RBAC permission every other RemoteStorage-primitive proxy in
// this package already needs — no new privilege class).
//
// This is a thin passthrough onto the SAME storage.Storage.
// UpdateUserIfActiveStateMatches primitive internal/core/users.go's UpdateUser
// already calls against a local backend — no update-request validation
// (uniqueness checks, which fields the original caller actually meant to
// change) is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend. This
// handler only persists the row it's given, conditionally.
//
// Deliberately NOT the human-facing PUT /api/v1/users/{id} route
// (users_crud.go's UserHandler.UpdateUser): that route re-runs the UPSTREAM
// server's own core.KeyorixCore.UpdateUser end to end against the request
// body it receives — the wrong semantics for a raw conditional-write
// passthrough whose caller has already done all of that validation itself
// against proxied reads and only needs the final persist to be atomic. See
// remote_users.go's UpdateUserIfActiveStateMatches doc for the full reasoning
// (mirrors machine_identities_proxy.go's TransitionMachineIdentityStateProxy
// vs. UpdateMachineIdentityProxy distinction exactly).
//
// Response envelope: like every other proxy in this package, this does NOT use
// the package's generic sendSuccess/sendError helpers — it constructs the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses.
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// userActiveTransitionProxyBody mirrors RemoteStorage's
// userActiveTransitionWireRequest exactly (internal/storage/store/
// remote_users.go) — the full row UpdateUser already mutated in memory, plus
// the fromActive value it observed under GetUser before applying any of the
// request's field changes. UpdatedAt is carried explicitly since this route
// makes no server-side core.UpdateUser call to recompute it — see
// remote_users.go's userActiveTransitionWireRequest doc.
type userActiveTransitionProxyBody struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	Active      bool      `json:"active"`
	UpdatedAt   time.Time `json:"updated_at"`
	FromActive  bool      `json:"from_active"`
}

// duplicateUsernameProxyCode is the machine-readable error code
// UpdateUserIfActiveStateMatchesProxy returns when the username uniqueness
// pre-check below finds a conflict — mirroring duplicateEmailProxyCode's
// existing pattern for the same class of check.
const duplicateUsernameProxyCode = "DUPLICATE_USERNAME"

// UpdateUserIfActiveStateMatchesProxy handles PUT
// /api/v1/system/users/{id}/active-transition. Runs the SAME conditional
// "WHERE id = ? AND is_active = ?" write core.KeyorixCore.UpdateUser already
// relies on against a local backend when a request touches IsActive — see the
// package doc for why this is a dedicated route rather than a generic
// UpdateUser proxy.
//
// #G79: UpdateUser's own uniqueness pre-check (GetUserByUsername/
// GetUserByEmail against any OTHER row before persisting) was missing here —
// a caller reachable directly via system.write (bypassing the calling
// server's own UpdateUser) could otherwise attempt to set username/email to a
// value already held by a different user. The DB's own partial unique
// indexes still prevent a SILENT duplicate either way, but without this
// check the conflict surfaces as an opaque 500 storage error instead of the
// same 409 UpdateUser gives locally. Re-run the same two lookups here.
func (h *UserHandler) UpdateUserIfActiveStateMatchesProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	var body userActiveTransitionProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Username != "" {
		if existing, err := h.coreService.Storage().GetUserByUsername(r.Context(), body.Username); err == nil && existing != nil && existing.ID != uint(id) {
			writeRemoteAPIError(w, http.StatusConflict, duplicateUsernameProxyCode, "username already exists")
			return
		}
	}
	if body.Email != "" {
		if existing, err := h.coreService.Storage().GetUserByEmail(r.Context(), body.Email); err == nil && existing != nil && existing.ID != uint(id) {
			writeRemoteAPIError(w, http.StatusConflict, duplicateEmailProxyCode, storage.ErrDuplicateEmail.Error())
			return
		}
	}
	user := &models.User{
		ID:          uint(id),
		Username:    body.Username,
		Email:       body.Email,
		DisplayName: body.DisplayName,
		IsActive:    body.Active,
		UpdatedAt:   body.UpdatedAt,
	}
	matched, err := h.coreService.Storage().UpdateUserIfActiveStateMatches(r.Context(), user, body.FromActive)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateEmail) {
			writeRemoteAPIError(w, http.StatusConflict, duplicateEmailProxyCode, storage.ErrDuplicateEmail.Error())
			return
		}
		log.Printf("users proxy: active-state transition failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}
