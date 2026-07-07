// scheduler_lock_proxy.go — server-side endpoints backing RemoteStorage's
// TryAcquireSchedulerLock/ReleaseSchedulerLock (#530).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) runs
// EVERY background scheduler unconditionally (server/main.go), each wrapped in
// storage.Storage's single-replica-gating WithSchedulerLock (ADR-039) — but
// RemoteStorage had no server endpoint to call at all for it, so every one of
// those schedulers (retention purge, auto-rotation, recertification, dynamic-
// secret sweep, JIT-access expiry, login-attempt prune, anomaly detection,
// reminders, compliance digest, evidence delivery) failed to even ACQUIRE the
// lock on every tick, never mind run — including already-remote-proxied work
// like #520's retention purge, whose own (correct) proxy logic never got a
// chance to run. These two routes (registered in server/http/router.go under
// /api/v1/system/scheduler-lock, gated on the existing system.read/
// system.write RBAC permissions — the SAME credential a RemoteStorage client
// already needs for every other proxied call, so this introduces no new
// privilege class) close that gap.
//
// Atomicity: unlike a plain CRUD proxy, a distributed lock's acquire step
// cannot be "check, then write" over two separate remote calls — that would
// trivially reopen the exact race the lock exists to prevent (two callers,
// or a spoke and the hub, both believing they won). Each handler below calls
// exactly ONE storage.Storage method that performs its ENTIRE conditional
// decision (acquire vs. reject vs. reclaim-expired, or release-iff-still-owned)
// server-side inside a single transaction/statement — see
// internal/storage/store/local_scheduler_lock_lease.go's package doc and
// method comments for the full atomicity analysis. No lock POLICY (which key,
// how long to hold it, when to renew) is made here; that stays entirely in the
// CALLING server's own RemoteStorage.WithSchedulerLock, exactly as
// LocalStorage.WithSchedulerLock decides it against a local backend.
//
// Response envelope: like the other proxies (see login_attempts_proxy.go),
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// use writeRemoteAPISuccess/writeRemoteAPIError, the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// schedulerLockAcquireBody is the wire body for POST
// /api/v1/system/scheduler-lock/acquire.
type schedulerLockAcquireBody struct {
	Key       int64  `json:"key"`
	Holder    string `json:"holder"`
	TTLMillis int64  `json:"ttl_millis"`
}

// AcquireSchedulerLockProxy handles POST /api/v1/system/scheduler-lock/acquire.
// It calls storage.TryAcquireSchedulerLock directly, so it performs the SAME
// atomic acquire-or-renew-or-reclaim decision local_scheduler_lock_lease.go's
// own TryAcquireSchedulerLock does — the exclusivity guarantee
// RemoteStorage.WithSchedulerLock depends on survives this HTTP hop unchanged.
func (h *AuthHandler) AcquireSchedulerLockProxy(w http.ResponseWriter, r *http.Request) {
	var body schedulerLockAcquireBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Holder == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "holder is required")
		return
	}
	if body.TTLMillis <= 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "ttl_millis must be positive")
		return
	}
	acquired, err := h.coreService.Storage().TryAcquireSchedulerLock(r.Context(), body.Key, body.Holder, time.Duration(body.TTLMillis)*time.Millisecond)
	if err != nil {
		log.Printf("scheduler-lock proxy: acquire failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"acquired": acquired})
}

// schedulerLockReleaseBody is the wire body for POST
// /api/v1/system/scheduler-lock/release.
type schedulerLockReleaseBody struct {
	Key    int64  `json:"key"`
	Holder string `json:"holder"`
}

// ReleaseSchedulerLockProxy handles POST /api/v1/system/scheduler-lock/release.
// It calls storage.ReleaseSchedulerLock directly, so a release for a lock this
// holder does not (or no longer) own is a silent no-op here too, exactly as
// local_scheduler_lock_lease.go's own ReleaseSchedulerLock behaves.
func (h *AuthHandler) ReleaseSchedulerLockProxy(w http.ResponseWriter, r *http.Request) {
	var body schedulerLockReleaseBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Holder == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "holder is required")
		return
	}
	if err := h.coreService.Storage().ReleaseSchedulerLock(r.Context(), body.Key, body.Holder); err != nil {
		log.Printf("scheduler-lock proxy: release failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"released": true})
}
