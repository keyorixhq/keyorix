// login_attempts_proxy.go — server-side endpoints backing RemoteStorage's
// RecordLoginAttempt/CountRecentLoginAttempts/PruneLoginAttempts (#452 follow-up).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies its
// OWN per-IP login/password-reset rate-limit bookkeeping to whichever upstream server
// it's configured against, through these three routes (registered in
// server/http/router.go under /api/v1/system/login-attempts, gated on the existing
// system.read/system.write RBAC permissions — the same credential a RemoteStorage
// client already needs for every other proxied call, e.g. full user CRUD, so this
// introduces no new privilege class).
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// (RecordLoginAttempt/CountRecentLoginAttempts/PruneLoginAttempts) the local
// /auth/login path already uses (ADR-040) — no rate-limiting POLICY decision (the
// threshold, the window) is made here; that stays entirely in the CALLING server's
// own internal/core.KeyorixCore, exactly as it does against a local backend. This
// file only persists/counts/prunes the raw (key, timestamp) rows. The one exception
// is PruneLoginAttemptsProxy (CORE-RATE-003): it deliberately does NOT call
// storage.Storage.PruneLoginAttempts directly, because the request body's `before`
// is attacker-influenced and an unbounded passthrough let any system.write
// principal wipe the entire table on demand. It routes through
// core.KeyorixCore.PruneLoginAttempts instead, which clamps the cutoff and audits
// the deletion — see that handler's own doc comment.
//
// Response envelope: these three handlers deliberately do NOT use the package's
// generic sendSuccess/sendError helpers. Those write {"data":...}/{"error":"...",
// "message":...,"code":...} — a shape the rest of this server's handlers use for the
// web UI and CLI — which does not match the {"success":bool,"data":...,
// "error":{"code","message"}} envelope internal/storage/remote.HTTPClient actually
// parses (its APIResponse/APIError types). Since these three endpoints exist solely
// to serve that wire protocol, they construct that exact envelope directly.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/keyorixhq/keyorix/server/middleware"
)

// remoteAPIResponse mirrors internal/storage/remote.APIResponse's wire shape.
type remoteAPIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func writeRemoteAPISuccess(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := json.NewEncoder(w).Encode(remoteAPIResponse{Success: true, Data: data}); err != nil {
		log.Printf("login-attempts proxy: error encoding response: %v", err)
	}
}

func writeRemoteAPIError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	resp := remoteAPIResponse{Success: false}
	resp.Error = &struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}{Code: code, Message: message}
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("login-attempts proxy: error encoding error response: %v", err)
	}
}

// loginAttemptRecordBody is the wire body for POST /api/v1/system/login-attempts.
type loginAttemptRecordBody struct {
	IP string    `json:"ip"`
	At time.Time `json:"at"`
}

// loginAttemptPruneBody is the wire body for POST /api/v1/system/login-attempts/prune.
type loginAttemptPruneBody struct {
	Before time.Time `json:"before"`
}

// RecordLoginAttemptProxy handles POST /api/v1/system/login-attempts.
func (h *AuthHandler) RecordLoginAttemptProxy(w http.ResponseWriter, r *http.Request) {
	var body loginAttemptRecordBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.IP == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "ip is required")
		return
	}
	if err := h.coreService.Storage().RecordLoginAttempt(r.Context(), body.IP, body.At); err != nil {
		log.Printf("login-attempts proxy: record failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"recorded": true})
}

// CountLoginAttemptsProxy handles GET /api/v1/system/login-attempts/count?ip=...&since=....
func (h *AuthHandler) CountLoginAttemptsProxy(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	sinceStr := r.URL.Query().Get("since")
	if ip == "" || sinceStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "ip and since query parameters are required")
		return
	}
	since, err := time.Parse(time.RFC3339Nano, sinceStr)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "since must be an RFC3339 timestamp")
		return
	}
	n, err := h.coreService.Storage().CountRecentLoginAttempts(r.Context(), ip, since)
	if err != nil {
		log.Printf("login-attempts proxy: count failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"count": n})
}

// PruneLoginAttemptsProxy handles POST /api/v1/system/login-attempts/prune.
//
// CORE-RATE-003: this used to call h.coreService.Storage().PruneLoginAttempts
// directly — an unbounded passthrough onto the raw storage primitive with the
// only validation being "before is non-zero". Any principal holding
// system.write (the group's baseline permission) could pass an arbitrary
// future `before` (e.g. year 2099) and wipe the ENTIRE login_attempts table
// on demand: every IP's failed-login counter reset to zero and the only
// record a brute-force campaign was ever attempted from any address erased,
// with no audit trail marking that the wipe occurred. It now routes through
// core.KeyorixCore.PruneLoginAttempts instead, which clamps the effective
// cutoff to never exceed `now - LoginWindow` (the maintenance sweep's own
// invariant — a caller here can only narrow the window, never widen it) and
// emits a `data.login_attempts_pruned` audit event (actor + row count +
// cutoff) whenever anything is actually removed.
func (h *AuthHandler) PruneLoginAttemptsProxy(w http.ResponseWriter, r *http.Request) {
	var body loginAttemptPruneBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Before.IsZero() {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "before is required")
		return
	}
	var actorID uint
	if userCtx := middleware.GetUserFromContext(r.Context()); userCtx != nil {
		actorID = userCtx.UserID
	}
	n, err := h.coreService.PruneLoginAttempts(r.Context(), body.Before, actorID)
	if err != nil {
		log.Printf("login-attempts proxy: prune failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"deleted": n})
}
