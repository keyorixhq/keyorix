// login_lockout_proxy.go — server-side endpoint backing RemoteStorage's
// UpdateLoginLockoutState (backlog #529, closing the #454 gap that left this one
// method a hard, permanent stub after login-attempts/setup-tokens/groups/etc. were
// each proxied in turn).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies its
// per-account login-lockout accounting write to whichever upstream server it's
// configured against, through this route (registered in server/http/router.go under
// /api/v1/system/users/{id}/login-lockout, gated on the existing system.read/
// system.write RBAC permissions — the SAME credential a RemoteStorage client already
// needs for every other proxied call, e.g. full user CRUD and the login-attempts
// proxy, so this introduces no new privilege class).
//
// This is a thin passthrough onto the SAME storage.Storage.UpdateLoginLockoutState
// primitive internal/core/login_lockout.go already calls against a local backend — no
// lockout POLICY decision (the failure threshold, the exponential cooldown, WHEN to
// trip or clear the lock) is made here; that stays entirely in the CALLING server's
// own internal/core.KeyorixCore, exactly as it does against a local backend. This
// handler only persists the four already-computed columns the caller hands it.
//
// Atomicity: LocalStorage.UpdateLoginLockoutState (internal/storage/store/
// local_users.go) is a single unconditional `UPDATE ... SET` over the four
// login-lockout columns — no server-side read-modify-write, no compare-and-set
// condition. Every caller in login_lockout.go already does its own
// read-increment-compute step under its own locking (LockUserForUpdate inside
// c.storage.WithTransaction, serialized additionally by the per-user loginFailureMu
// shard) and only then calls this method with the final values to persist. So a
// single HTTP round trip here preserves the LOCAL implementation's semantics exactly
// unchanged — unlike WebAuthn's AdvanceWebAuthnCredentialCounterProxy (a genuine
// compare-and-swap that needs the entire check-then-write to run in ONE request
// because RemoteStorage.WithTransaction is a no-op passthrough), there is no
// analogous race to reopen here: this handler does not need to re-derive or validate
// anything, it just writes the four values it was given.
//
// Response envelope: like every other proxy in this package, this does NOT use the
// package's generic sendSuccess/sendError helpers — it constructs the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
)

// loginLockoutUpdateProxyBody is the wire body for PUT
// /api/v1/system/users/{id}/login-lockout, mirroring
// storage.Storage.UpdateLoginLockoutState's four positional parameters exactly
// (attempts, lastFailedAt, lockedUntil, lockoutCount).
type loginLockoutUpdateProxyBody struct {
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LastFailedLoginAt   *time.Time `json:"last_failed_login_at"`
	LoginLockedUntil    *time.Time `json:"login_locked_until"`
	LoginLockoutCount   int        `json:"login_lockout_count"`
}

// UpdateLoginLockoutStateProxy handles PUT
// /api/v1/system/users/{id}/login-lockout.
func (h *AuthHandler) UpdateLoginLockoutStateProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	var body loginLockoutUpdateProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	err = h.coreService.Storage().UpdateLoginLockoutState(
		r.Context(), uint(id), body.FailedLoginAttempts, body.LastFailedLoginAt, body.LoginLockedUntil, body.LoginLockoutCount)
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		log.Printf("login-lockout proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}
