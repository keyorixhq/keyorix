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
// (the same conditional-vs-raw distinction machine_identities_proxy.go's
// TransitionMachineIdentityStateProxy drew against its own raw
// UpdateMachineIdentityProxy sibling before that sibling was deleted for
// having no live caller -- #1585, docs/adr-090-stale-fork-proxy-deletion.md).
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
	// #1542-shape guard (G80 overnight campaign, Tier 1 Group A #3): this route
	// never called the last-global-admin lockout guard core.UpdateUser's
	// deactivating branch applies (internal/core/users.go:384), so a caller could
	// deactivate the install's only admin with no protection. core.GuardLastAdminDeactivation
	// depends only on the target user ID (a target-state invariant, not a
	// caller-authority check -- see its doc), which is already the route's own
	// path parameter, so this closes the gap with no RemoteStorage wire-protocol
	// change.
	deactivating := body.FromActive && !body.Active
	if deactivating {
		if err := h.coreService.GuardLastAdminDeactivation(r.Context(), uint(id)); err != nil {
			writeRemoteAPIError(w, http.StatusForbidden, "LAST_ADMIN", clientSafe(err))
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
	// #1572: replicate core.UpdateUser's deactivating-branch side effect --
	// PAT/session revocation -- which a caller reaching this route directly
	// (bypassing core.UpdateUser, e.g. holding raw system.write without going
	// through the CLI's own core.UpdateUser call) would otherwise skip
	// entirely, leaving the deactivated user's PATs/sessions live. The two
	// core-level operations this calls (RevokeAllPersonalAccessTokensForUser/
	// DeleteSessionsForUserExcept, server/http/handlers/users_credentials_proxy.go)
	// already exist as safe, authorized, audited routes for exactly this
	// purpose (ADR-088's own costing for #1572: "the fix is calling those same
	// two already-safe internal/core operations directly, in sequence... no new
	// primitive needed") -- reused here as in-process calls, not a second HTTP
	// hop, since this handler already runs on the hub. Best-effort and
	// non-fatal, matching core.UpdateUser's own posture toward the identical
	// failure mode (internal/core/users.go's deactivating branch, lines
	// ~419-463): the deactivation itself already committed via the conditional
	// write above, and ValidateSessionToken/ValidatePATToken independently
	// re-check the live is_active flag on every use regardless of whether
	// revocation ran, so a failed best-effort revocation here leaves no live
	// credential, only a stale row. Only fires when matched is true (this
	// call's own CAS write actually won the race) and only on a real
	// true->false transition -- calling it on every request would revoke
	// credentials on no-op or reactivating calls too.
	if matched && deactivating {
		actorType, actorID := requestActorKindAndID(r)
		if _, err := h.coreService.RevokeAllPersonalAccessTokensForUser(r.Context(), actorType, actorID, uint(id)); err != nil {
			log.Printf("users proxy: active-state transition: best-effort PAT revocation failed for user %d: %v", id, err)
		}
		if err := h.coreService.DeleteSessionsForUserExcept(r.Context(), actorType, actorID, uint(id), 0); err != nil {
			log.Printf("users proxy: active-state transition: best-effort session revocation failed for user %d: %v", id, err)
		}
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}
