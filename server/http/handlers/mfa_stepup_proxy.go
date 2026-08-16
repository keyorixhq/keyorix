// mfa_stepup_proxy.go — server-side endpoints backing RemoteStorage's
// MFAStepUpGrant storage primitives:
// CreateMFAStepUpGrant / GetActiveMFAStepUpGrant / DeleteMFAStepUpGrantsFor /
// PruneMFAStepUpGrants.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies these calls to this server's real storage backend so that the MFA
// step-up gate works correctly in multi-node cluster deployments. Follows the
// same pattern as mfa_management_proxy.go: thin passthroughs onto
// storage.Storage, no policy decisions made here, system.read/system.write
// RBAC tier, exact {"success":bool,"data":...} envelope.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// mfaStepUpGrantProxyBody is the wire body for CreateMFAStepUpGrantProxy and
// is also used to parse GetActiveMFAStepUpGrantProxy's {user_id, now} pair.
type mfaStepUpGrantProxyBody struct {
	UserID    uint      `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// mfaStepUpGrantActiveProxyBody is the wire body for
// GetActiveMFAStepUpGrantProxy. It used to also carry a caller-supplied
// `now` forwarded straight into the expiry comparison — removed (G-wave6,
// same class as users_crud.go's mfaChallengeLookupBody and
// webauthn_proxy.go's webAuthnSessionConsumeProxyBody): a remote caller
// could manipulate the effective "current time" used to decide whether a
// step-up grant is still active, defeating the step-up TTL. This server now
// always uses its own clock for that comparison.
type mfaStepUpGrantActiveProxyBody struct {
	UserID uint `json:"user_id"`
}

// CreateMFAStepUpGrantProxy handles POST /api/v1/system/mfa/stepup-grants.
// Creates a new MFAStepUpGrant row and returns it with server-assigned fields.
func (h *AuthHandler) CreateMFAStepUpGrantProxy(w http.ResponseWriter, r *http.Request) {
	var body mfaStepUpGrantProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id is required")
		return
	}
	grant := &models.MFAStepUpGrant{
		UserID:    body.UserID,
		ExpiresAt: body.ExpiresAt,
	}
	if err := h.coreService.Storage().CreateMFAStepUpGrant(r.Context(), grant); err != nil {
		log.Printf("mfa stepup proxy: create grant failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, grant)
}

// GetActiveMFAStepUpGrantProxy handles POST
// /api/v1/system/mfa/stepup-grants/active. Returns the most recent
// non-expired grant for the given user, or null in the data field when none
// exists.
func (h *AuthHandler) GetActiveMFAStepUpGrantProxy(w http.ResponseWriter, r *http.Request) {
	var body mfaStepUpGrantActiveProxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id is required")
		return
	}
	// This server's own clock, never a caller-supplied value — see
	// mfaStepUpGrantActiveProxyBody's doc comment. LocalStorage's
	// GetActiveMFAStepUpGrant already normalizes this to .UTC() itself
	// (local_mfa_stepup_grant.go), matching models.MFAStepUpGrant's
	// BeforeSave UTC-normalization hook, so a plain time.Now() here is fine.
	grant, err := h.coreService.Storage().GetActiveMFAStepUpGrant(r.Context(), body.UserID, time.Now())
	if err != nil {
		log.Printf("mfa stepup proxy: get active grant failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	// grant is nil when no active grant exists; writeRemoteAPISuccess encodes
	// it as {"success":true,"data":null} which the remote client treats as
	// (nil, nil).
	writeRemoteAPISuccess(w, grant)
}

// DeleteMFAStepUpGrantsForProxy handles DELETE
// /api/v1/system/mfa/stepup-grants/{userId}. Removes all step-up grants for
// the given user (session revocation / security-incident response).
func (h *AuthHandler) DeleteMFAStepUpGrantsForProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user id")
		return
	}
	userID := uint(id)
	if err := h.coreService.Storage().DeleteMFAStepUpGrantsFor(r.Context(), userID); err != nil {
		log.Printf("mfa stepup proxy: delete grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// mfaStepUpGrantPruneBody is the wire body for POST /api/v1/system/mfa/stepup-grants/prune.
type mfaStepUpGrantPruneBody struct {
	Before time.Time `json:"before"`
}

// PruneMFAStepUpGrantsProxy handles POST /api/v1/system/mfa/stepup-grants/prune
// (store-mfa-002). Mirrors login_attempts_proxy.go's PruneLoginAttemptsProxy
// (CORE-RATE-003): deliberately does NOT call
// h.coreService.Storage().PruneMFAStepUpGrants directly with the request
// body's `before` — that value is attacker/caller-influenced (any
// system.write / node-credential principal), and an unbounded passthrough
// would let a caller wipe the entire mfa_stepup_grants table on demand. It
// routes through core.KeyorixCore.PruneMFAStepUpGrants instead, which clamps
// the effective cutoff to the configured/default retention window so a
// caller can only narrow the deletion window, never widen it.
func (h *AuthHandler) PruneMFAStepUpGrantsProxy(w http.ResponseWriter, r *http.Request) {
	var body mfaStepUpGrantPruneBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Before.IsZero() {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "before is required")
		return
	}
	// retention=0: this upstream server uses its own configured/default
	// retention window (see core.KeyorixCore.PruneMFAStepUpGrants), not one
	// dictated by the downstream caller.
	n, err := h.coreService.PruneMFAStepUpGrants(r.Context(), 0, body.Before)
	if err != nil {
		log.Printf("mfa stepup proxy: prune failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]int64{"deleted": n})
}
