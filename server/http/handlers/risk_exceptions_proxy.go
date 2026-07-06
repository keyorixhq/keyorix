// risk_exceptions_proxy.go — server-side endpoints backing RemoteStorage's
// CreateRiskException/GetRiskException/ListRiskExceptions/UpdateRiskException
// (finding #519).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its risk-exception (ISO 27001 A.5.8 risk-register) storage calls to whichever
// upstream server it's configured against, through these routes (registered in
// server/http/router.go under /api/v1/system/risk-exceptions, gated on the
// existing system.read/system.write RBAC permissions — the SAME credential a
// RemoteStorage client already needs for every other proxied call, e.g. full user
// CRUD, dynamic-secrets CRUD (round-116 finding), so this introduces no new
// privilege class). Mirrors dynamic_secrets_proxy.go/project_memberships_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/risk_exceptions.go already uses against a local backend — NO
// risk-exception POLICY decision (title/category/justification validation, the
// expiry-in-the-future and max-365-day-sunset bounds, dual-control approval —
// the creator can never approve their own exception — or the effective-status
// computation from the revoked flag + expiry) is made here; all of that stays
// entirely in the CALLING server's own internal/core.KeyorixCore, exactly as it
// does against a local backend.
//
// This also means the human-facing /api/v1/risk-exceptions routes
// (server/http/handlers/risk_exceptions.go, DashboardHandler.ListRiskExceptions/
// CreateRiskException/ApproveRiskException/RevokeRiskException) are NOT reused
// for this proxy: those bake in exactly the policy decisions above (dual-control
// approval, expiry/duration validation, actor-identity extraction from the HTTP
// caller's own session) against THIS server's own core — the wrong semantics for
// a raw storage-primitive passthrough whose caller already ran all of that
// decision-making on the downstream side and only needs this server to
// persist/return the resulting row. Exactly the same class of mistake the
// human-facing /groups routes were for #514's Group-CRUD proxy fix.
//
// Atomicity: storage.Storage.UpdateRiskException (local_risk_exceptions.go) is an
// unconditional full-row `Save`, not a conditional/optimistic-concurrency write —
// there is no LockXForUpdate/SELECT ... FOR UPDATE anywhere in this subsystem to
// preserve across the wire. internal/core.RevokeRiskException/ApproveRiskException
// already re-fetch the exception and check its revoked/approved/expiry state
// before mutating it — a check-then-act sequence with exactly the same (small,
// pre-existing, accepted) race window against a local backend as against this
// proxy. This fix preserves that behavior exactly rather than introducing a
// stricter guarantee the local backend itself doesn't have (mirrors
// dynamic_secrets_proxy.go's UpdateDynamicSecretConfigProxy/
// UpdateDynamicSecretLeaseProxy reasoning).
//
// Response envelope: like dynamic_secrets_proxy.go/project_memberships_proxy.go,
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
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

// riskExceptionProxyWire mirrors models.RiskException's fields exactly
// (snake_case) — the wire shape internal/storage/store/remote_risk_exceptions.go
// sends/expects. Named explicitly (rather than relying on a direct model
// marshal) to match every other proxy handler's convention in this package.
type riskExceptionProxyWire struct {
	ID            uint       `json:"id"`
	Title         string     `json:"title"`
	Category      string     `json:"category"`
	Reference     string     `json:"reference,omitempty"`
	Justification string     `json:"justification"`
	CreatedBy     uint       `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	Revoked       bool       `json:"revoked"`
	RevokedBy     uint       `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	Approved      bool       `json:"approved"`
	ApprovedBy    uint       `json:"approved_by,omitempty"`
	ApprovedAt    *time.Time `json:"approved_at,omitempty"`
}

func newRiskExceptionProxyWire(e *models.RiskException) riskExceptionProxyWire {
	return riskExceptionProxyWire{
		ID:            e.ID,
		Title:         e.Title,
		Category:      e.Category,
		Reference:     e.Reference,
		Justification: e.Justification,
		CreatedBy:     e.CreatedBy,
		CreatedAt:     e.CreatedAt,
		ExpiresAt:     e.ExpiresAt,
		Revoked:       e.Revoked,
		RevokedBy:     e.RevokedBy,
		RevokedAt:     e.RevokedAt,
		Approved:      e.Approved,
		ApprovedBy:    e.ApprovedBy,
		ApprovedAt:    e.ApprovedAt,
	}
}

func (w riskExceptionProxyWire) toModel() *models.RiskException {
	return &models.RiskException{
		ID:            w.ID,
		Title:         w.Title,
		Category:      w.Category,
		Reference:     w.Reference,
		Justification: w.Justification,
		CreatedBy:     w.CreatedBy,
		CreatedAt:     w.CreatedAt,
		ExpiresAt:     w.ExpiresAt,
		Revoked:       w.Revoked,
		RevokedBy:     w.RevokedBy,
		RevokedAt:     w.RevokedAt,
		Approved:      w.Approved,
		ApprovedBy:    w.ApprovedBy,
		ApprovedAt:    w.ApprovedAt,
	}
}

// CreateRiskExceptionProxy handles POST /api/v1/system/risk-exceptions. Persists
// the caller's already-fully-built (and already-validated) exception row as-is —
// see the package doc for why this is NOT a re-run of
// core.CreateRiskException's validation.
func (h *DashboardHandler) CreateRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	var body riskExceptionProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Title == "" || body.Justification == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "title and justification are required")
		return
	}
	created, err := h.coreService.Storage().CreateRiskException(r.Context(), body.toModel())
	if err != nil {
		log.Printf("risk-exceptions proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newRiskExceptionProxyWire(created))
}

// GetRiskExceptionProxy handles GET /api/v1/system/risk-exceptions/{id}.
func (h *DashboardHandler) GetRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid exception id")
		return
	}
	e, err := h.coreService.Storage().GetRiskException(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "risk exception not found")
			return
		}
		log.Printf("risk-exceptions proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newRiskExceptionProxyWire(e))
}

// ListRiskExceptionsProxy handles GET
// /api/v1/system/risk-exceptions?active_only=true|false.
func (h *DashboardHandler) ListRiskExceptionsProxy(w http.ResponseWriter, r *http.Request) {
	// activeOnly defaults to false (return every non-revoked row, matching
	// storage.ListRiskExceptions' own contract) unless the caller explicitly asks
	// to exclude revoked rows.
	activeOnly := r.URL.Query().Get("active_only") == "true"
	rows, err := h.coreService.Storage().ListRiskExceptions(r.Context(), activeOnly)
	if err != nil {
		log.Printf("risk-exceptions proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]riskExceptionProxyWire, 0, len(rows))
	for _, e := range rows {
		wire = append(wire, newRiskExceptionProxyWire(e))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"exceptions": wire})
}

// UpdateRiskExceptionProxy handles PUT /api/v1/system/risk-exceptions/{id}. A raw
// persist (storage.Storage.UpdateRiskException is an unconditional full-row Save,
// matching LocalStorage's own semantics exactly) — see the package doc for why no
// conditional write is needed here.
func (h *DashboardHandler) UpdateRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid exception id")
		return
	}
	var body riskExceptionProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateRiskException(r.Context(), body.toModel()); err != nil {
		log.Printf("risk-exceptions proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}
