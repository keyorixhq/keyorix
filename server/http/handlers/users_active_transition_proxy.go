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
	"github.com/keyorixhq/keyorix/internal/identity"
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
	// #1642: this route bypasses core.UpdateUser's own fold entirely (it goes
	// straight to storage.UpdateUserIfActiveStateMatches, a full-row replace —
	// see its own doc comment), so a stale/empty UsernameFolded or
	// EmailFolded here would silently break every future lookup for this user
	// via GetUserByUsername/GetUserByEmail. Fold whatever the wire body
	// carries; Email may legitimately be empty (some accounts have none,
	// same as core.UpdateUser tolerates), in which case EmailFolded stays
	// empty too, matching ensureUserEmailIndex's own empty-email exclusion.
	var foldedUsername, foldedEmail identity.FoldedName
	if body.Username != "" {
		var ferr error
		foldedUsername, ferr = identity.NewFoldedName(body.Username)
		if ferr != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid username: "+ferr.Error())
			return
		}
	}
	if body.Email != "" {
		var ferr error
		foldedEmail, ferr = identity.NewFoldedName(body.Email)
		if ferr != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid email: "+ferr.Error())
			return
		}
	}
	user := &models.User{
		ID:             uint(id),
		Username:       body.Username,
		UsernameFolded: foldedUsername.Folded(),
		Email:          body.Email,
		EmailFolded:    foldedEmail.Folded(),
		DisplayName:    body.DisplayName,
		IsActive:       body.Active,
		UpdatedAt:      body.UpdatedAt,
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
	// #1572, corrected 2026-09-03: replicate core.UpdateUser's deactivating-
	// branch side effect -- PAT/session revocation -- which a caller reaching
	// this route directly (bypassing core.UpdateUser) would otherwise skip
	// entirely. The original fix called core.RevokeAllPersonalAccessTokensForUser/
	// core.DeleteSessionsForUserExcept, believing them "already-safe" reuse --
	// but those two specifically gate on requireUserCredentialsRevokeAuthority
	// (users.write), which is the RIGHT ceiling for a caller invoking
	// revocation as its own standalone action, and the WRONG one here: this
	// route's own gate is the broader, non-project-scoped system.write every
	// /system proxy accepts, not users.write specifically, so a caller
	// reaching this route without users.write hit that ceiling on EVERY
	// deactivation, had the failure logged and swallowed as "best-effort,"
	// and left the deactivated user's session warm-cache-usable for up to 30s
	// (core.UpdateUser's own local branch evicts the session cache
	// unconditionally, before the revocation attempt -- this proxy's use of
	// the ceiling-gated wrappers meant that eviction never ran at all when
	// the ceiling rejected the call, since the wrapper returns before doing
	// anything). core.RevokeUserCredentialsForDeactivation calls storage
	// directly instead, exactly like core.UpdateUser's own deactivating
	// branch does -- see its doc for why no separate ceiling belongs here:
	// revocation is a mandatory consequence of a deactivation already
	// committed by the write above, not an independent decision. Only fires
	// when matched is true (this call's own CAS write actually won the race)
	// and only on a real true->false transition -- calling it on every
	// request would revoke credentials on no-op or reactivating calls too.
	if matched && deactivating {
		h.coreService.RevokeUserCredentialsForDeactivation(r.Context(), uint(id))
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}
