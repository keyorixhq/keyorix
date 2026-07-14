// access_request_proxy.go — server-side endpoints backing RemoteStorage's
// CreateAccessRequest/GetAccessRequest/UpdateAccessRequest/ListAccessRequests/
// CreateAccessRequestApproval/ListAccessRequestApprovals (#523).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies its self-service access-request storage calls to whichever upstream
// server it's configured against, through these six routes (registered in
// server/http/router.go under /api/v1/system/access-requests, gated on the
// existing system.read/system.write RBAC permissions — the SAME credential a
// RemoteStorage client already needs for every other proxied call, e.g. full
// user CRUD). This mirrors invitations_proxy.go exactly.
//
// Deliberately NOT reused: the existing human-facing
// /api/v1/projects/{id}/access-requests* routes (ListAccessRequests/
// CreateAccessRequest/ResolveAccessRequest/WithdrawAccessRequest in
// invitations.go). Those handlers call straight into
// core.KeyorixCore.RequestProjectAccess/ApproveAccessRequestWithExpiry/
// RejectAccessRequest/WithdrawAccessRequest — full business logic that writes
// its own audit-log events, sends its own notifications, and resolves the
// acting user from THIS server's own request context
// (middleware.GetUserFromContext). Routing the proxy through them would (a)
// double-apply that business logic server-side on top of whatever the
// DOWNSTREAM server's core.KeyorixCore already did before ever making the
// HTTP call, and (b) attribute every audit event/notification to the wrong
// actor — the hub's own service credential, not the real requester/approver
// the downstream server is acting on behalf of. These six routes below are
// raw passthroughs onto storage.Storage's own CreateAccessRequest/
// GetAccessRequest/UpdateAccessRequest/ListAccessRequests/
// CreateAccessRequestApproval/ListAccessRequestApprovals instead — exactly the
// primitives internal/core/invitations.go and classification_gate.go already
// call against a local backend. No access-request POLICY decision (dual-control
// threshold, maker-checker, TTL/expiry, the role grant itself, audit writes,
// notifications) is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// UpdateAccessRequestProxy calls storage.UpdateAccessRequest directly, so it
// inherits local_invitations.go's conditional `WHERE id = ? AND state =
// 'pending'` write verbatim — the #277 approve/reject/withdraw race guarantee
// survives this HTTP hop unchanged. CreateAccessRequestApprovalProxy similarly
// inherits the DB-level unique-index-backed ON CONFLICT DO NOTHING insert. See
// remote_invitations.go's package doc for the full atomicity analysis.
//
// Response envelope: like invitations_proxy.go, these do NOT use the package's
// generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)


// accessRequestProxyWire mirrors models.AccessRequest's PERSISTED fields
// exactly (snake_case) — the wire shape
// internal/storage/store/remote_invitations.go's accessRequestWire
// sends/expects. ApprovalsReceived/RequiredApprovals are excluded: they are
// tagged `gorm:"-"` on the model itself (transient, computed by
// internal/core/invitations.go only on a value about to be returned to an
// HTTP caller), so there is nothing here to persist or round-trip.
type accessRequestProxyWire struct {
	ID            uint       `json:"id"`
	ProjectID     uint       `json:"project_id"`
	UserID        uint       `json:"user_id"`
	SuggestedRole string     `json:"suggested_role"`
	GrantedRole   string     `json:"granted_role"`
	SecretID      *uint      `json:"secret_id"`
	State         string     `json:"state"`
	Reason        string     `json:"reason"`
	ResolvedBy    uint       `json:"resolved_by"`
	ExpiresAt     *time.Time `json:"expires_at"`
	CreatedAt     time.Time  `json:"created_at"`
	ResolvedAt    *time.Time `json:"resolved_at"`
}

func newAccessRequestProxyWire(req *models.AccessRequest) accessRequestProxyWire {
	return accessRequestProxyWire{
		ID:            req.ID,
		ProjectID:     req.ProjectID,
		UserID:        req.UserID,
		SuggestedRole: req.SuggestedRole,
		GrantedRole:   req.GrantedRole,
		SecretID:      req.SecretID,
		State:         req.State,
		Reason:        req.Reason,
		ResolvedBy:    req.ResolvedBy,
		ExpiresAt:     req.ExpiresAt,
		CreatedAt:     req.CreatedAt,
		ResolvedAt:    req.ResolvedAt,
	}
}

func (w accessRequestProxyWire) toModel() *models.AccessRequest {
	return &models.AccessRequest{
		ID:            w.ID,
		ProjectID:     w.ProjectID,
		UserID:        w.UserID,
		SuggestedRole: w.SuggestedRole,
		GrantedRole:   w.GrantedRole,
		SecretID:      w.SecretID,
		State:         w.State,
		Reason:        w.Reason,
		ResolvedBy:    w.ResolvedBy,
		ExpiresAt:     w.ExpiresAt,
		CreatedAt:     w.CreatedAt,
		ResolvedAt:    w.ResolvedAt,
	}
}

// accessRequestApprovalProxyWire mirrors models.AccessRequestApproval's
// fields exactly (snake_case).
type accessRequestApprovalProxyWire struct {
	ID         uint      `json:"id"`
	RequestID  uint      `json:"request_id"`
	ApproverID uint      `json:"approver_id"`
	CreatedAt  time.Time `json:"created_at"`
}

func newAccessRequestApprovalProxyWire(a *models.AccessRequestApproval) accessRequestApprovalProxyWire {
	return accessRequestApprovalProxyWire{
		ID:         a.ID,
		RequestID:  a.RequestID,
		ApproverID: a.ApproverID,
		CreatedAt:  a.CreatedAt,
	}
}

// validAccessRequestTargetState reports whether s is a state this proxy may
// WRITE via UpdateAccessRequestProxy. "pending" is deliberately excluded — it
// is only ever the initial state CreateAccessRequest persists, never a target
// of an UPDATE (every real transition in internal/core/invitations.go and
// classification_gate.go moves AWAY from pending), so accepting it here would
// let a caller resurrect an already-resolved request back to pending instead
// of merely transitioning it forward.
func validAccessRequestTargetState(s string) bool {
	switch s {
	case "approved", "rejected", "withdrawn", "expired":
		return true
	default:
		return false
	}
}

// CreateAccessRequestProxy handles POST /api/v1/system/access-requests. See
// the package doc for why this persists the caller's already-fully-built
// access request as-is (a raw storage-layer create) rather than routing
// through RequestProjectAccess/RequestSecretAccess's business logic (audit
// writes, notifications) a second time.
func (h *CatalogHandler) CreateAccessRequestProxy(w http.ResponseWriter, r *http.Request) {
	var body accessRequestProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.ProjectID == 0 || body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id and user_id are required")
		return
	}
	if body.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state is required")
		return
	}
	created, err := h.coreService.Storage().CreateAccessRequest(r.Context(), body.toModel())
	if err != nil {
		log.Printf("access-requests proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessRequestProxyWire(created))
}

// GetAccessRequestProxy handles GET /api/v1/system/access-requests/{id}.
func (h *CatalogHandler) GetAccessRequestProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidAccessRequestID)
		return
	}
	req, err := h.coreService.Storage().GetAccessRequest(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access request not found")
			return
		}
		log.Printf("access-requests proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessRequestProxyWire(req))
}

// UpdateAccessRequestProxy handles PUT /api/v1/system/access-requests/{id}. It
// performs the SAME conditional `WHERE id = ? AND state = 'pending'` write
// LocalStorage's own UpdateAccessRequest does (h.coreService.Storage() reaches
// the identical storage.Storage primitive this server's local
// /projects/{id}/access-requests* paths use), returning whether it actually
// matched a still-pending row — the single round trip a concurrent
// approve/reject/withdraw race resolves in (#277).
func (h *CatalogHandler) UpdateAccessRequestProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidAccessRequestID)
		return
	}
	var body accessRequestProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if !validAccessRequestTargetState(body.State) {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state must be one of approved, rejected, withdrawn, expired")
		return
	}
	body.ID = uint(id)
	updated, err := h.coreService.Storage().UpdateAccessRequest(r.Context(), body.toModel())
	if err != nil {
		log.Printf("access-requests proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": updated})
}

// ListAccessRequestsProxy handles GET
// /api/v1/system/access-requests?project_id=X.
func (h *CatalogHandler) ListAccessRequestsProxy(w http.ResponseWriter, r *http.Request) {
	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id query parameter is required")
		return
	}
	projectID, err := strconv.ParseUint(projectIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return
	}
	rows, err := h.coreService.Storage().ListAccessRequests(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("access-requests proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]accessRequestProxyWire, 0, len(rows))
	for _, req := range rows {
		wire = append(wire, newAccessRequestProxyWire(req))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"access_requests": wire})
}

// CreateAccessRequestApprovalProxy handles POST
// /api/v1/system/access-requests/{id}/approvals. It performs the SAME
// INSERT ... ON CONFLICT (request_id, approver_id) DO NOTHING
// local_invitations.go's CreateAccessRequestApproval does, backed by the
// DB-level unique index — a duplicate sign-off from the same approver is a
// benign no-op here exactly as it is locally.
func (h *CatalogHandler) CreateAccessRequestApprovalProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidAccessRequestID)
		return
	}
	var body accessRequestApprovalProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.ApproverID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "approver_id is required")
		return
	}
	approval := &models.AccessRequestApproval{
		RequestID:  uint(id),
		ApproverID: body.ApproverID,
		CreatedAt:  body.CreatedAt,
	}
	if err := h.coreService.Storage().CreateAccessRequestApproval(r.Context(), approval); err != nil {
		log.Printf("access-requests proxy: create approval failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newAccessRequestApprovalProxyWire(approval))
}

// ListAccessRequestApprovalsProxy handles GET
// /api/v1/system/access-requests/{id}/approvals.
func (h *CatalogHandler) ListAccessRequestApprovalsProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidAccessRequestID)
		return
	}
	rows, err := h.coreService.Storage().ListAccessRequestApprovals(r.Context(), uint(id))
	if err != nil {
		log.Printf("access-requests proxy: list approvals failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]accessRequestApprovalProxyWire, 0, len(rows))
	for _, a := range rows {
		wire = append(wire, newAccessRequestApprovalProxyWire(a))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"approvals": wire})
}
