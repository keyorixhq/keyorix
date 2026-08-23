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
// Atomicity: storage.Storage.UpdateRiskException (local_risk_exceptions.go)
// remains an unconditional full-row `Save`, but RevokeRiskException/
// ApproveRiskException (internal/core/risk_exceptions.go) no longer call it for
// their own revoke/approve transitions — a CodeQL query
// (StateTransitionMissingCAS.ql) confirmed the read-then-conditionally-
// mutate-then-Save sequence those two functions ran was a real TOCTOU: two
// callers racing the same exception (e.g. one admin revoking while another is
// mid-approve) could silently clobber each other's write, no error to either
// side. RevokeRiskExceptionIfNotRevoked/ApproveRiskExceptionIfPending
// (storage.Storage; implemented in local_risk_exceptions.go as a conditional
// GORM UPDATE) close it exactly like UpdateProjectInvitation's
// `WHERE id = ? AND state = 'pending'` (#412) and TransitionMachineIdentityState's
// `WHERE id = ? AND state = ?` (#388) did for their own TOCTOU classes.
// RevokeRiskExceptionProxy/ApproveRiskExceptionProxy below are the dedicated
// single-round-trip routes backing those two methods for RemoteStorage — see
// their own doc comments.
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

// CreateRiskExceptionProxy handles POST /api/v1/system/risk-exceptions. Routes
// through core.KeyorixCore.CreateRiskException (not a bare
// storage.CreateRiskException) so the title/category/justification validation
// and the expiry-in-the-future / max-365-day-sunset bounds also cover an
// exception created via node-sync (#G79) — the previous raw persist let a
// caller mint an already-approved or already-revoked exception, or one with an
// expiry far in the future, by simply setting those fields on the wire body.
func (h *DashboardHandler) CreateRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	var body riskExceptionProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Title == "" || body.Justification == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "title and justification are required")
		return
	}
	created, err := h.coreService.CreateRiskException(r.Context(), actorID(r), body.Title, body.Category, body.Reference, body.Justification, body.ExpiresAt)
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
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidExceptionID)
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

// UpdateRiskExceptionProxy (#G79 — REMOVED, not fixed-in-place): this route
// used to accept a client-supplied models.RiskException and persist it as an
// unconditional full-row Save with no auth/business-logic decision at all —
// the mandatory dual-control invariant (approver != creator) and every other
// field were entirely caller-controlled. It is not merely fixed but deleted
// (see router.go) because it has NO legitimate caller: core.RevokeRiskException/
// ApproveRiskException (the only two functions that ever mutate an existing
// risk exception) both moved to the conditional
// RevokeRiskExceptionIfNotRevoked/ApproveRiskExceptionIfPending primitives
// below years ago (StateTransitionMissingCAS.ql fix) and have never called
// storage.UpdateRiskException since — a repo-wide search found no caller of
// it anywhere, local or remote. RemoteStorage.UpdateRiskException (the
// client-side stub) and the storage.Storage interface method are left in
// place — dead but harmless, since nothing reaches them without this route —
// removing those is an unrelated dead-code cleanup, not a security fix.

// RevokeRiskExceptionProxy handles PUT /api/v1/system/risk-exceptions/{id}/revoke.
// Routes through core.KeyorixCore.RevokeRiskException (not the raw conditional
// storage primitive with a client-supplied row) so the already-revoked/
// already-expired preconditions and the audit-event write also cover a revoke
// via node-sync (#G79); RevokeRiskException re-fetches the row and resolves
// RevokedBy/RevokedAt itself, so none of that is accepted from the wire body.
func (h *DashboardHandler) RevokeRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidExceptionID)
		return
	}
	if err := h.coreService.RevokeRiskException(r.Context(), actorID(r), uint(id)); err != nil {
		log.Printf("risk-exceptions proxy: revoke failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": true})
}

// ApproveRiskExceptionProxy handles PUT /api/v1/system/risk-exceptions/{id}/approve.
// Routes through core.KeyorixCore.ApproveRiskException (not the raw conditional
// storage primitive with a client-supplied row) so the mandatory dual-control
// invariant (actorID must differ from the exception's CreatedBy) — previously
// never checked at all by this proxy — also covers an approval via node-sync
// (#G79); ApproveRiskException re-fetches the row and resolves
// Approved/ApprovedBy/ApprovedAt itself, so none of that (nor any other field
// on the row) is accepted from the wire body anymore. #1524 finding (c): a
// node credential relaying a human-created exception collided with neither
// side of the old actorID==e.CreatedBy comparison, so approval proceeded with
// no authority check. isMachineActor(r) closes it unconditionally — dual
// control requires a different HUMAN, which a machine credential can never
// be, independent of the self-approval comparison.
func (h *DashboardHandler) ApproveRiskExceptionProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidExceptionID)
		return
	}
	if err := h.coreService.ApproveRiskException(r.Context(), actorID(r), isMachineActor(r), uint(id)); err != nil {
		log.Printf("risk-exceptions proxy: approve failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": true})
}
