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
	"github.com/keyorixhq/keyorix/internal/core"
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
//
// #1529-shape guard: every legitimate creation path (RequestProjectAccess,
// RequestSecretAccess) always creates with State=pending -- approval is a
// SEPARATE, subsequent action (UpdateAccessRequestProxy), never something the
// creator decides for themselves. Before this fix, State was caller-writable
// with no restriction: POST {state:"approved", secret_id, user_id:self}
// bypassed ApproveSecretAccessRequest's admin-authority + maker≠checker dual
// control entirely, in one call. Reject anything but "pending" -- this needs
// no RemoteStorage wire-protocol change, since the only real caller (a
// downstream node's own RequestProjectAccess/RequestSecretAccess, relayed)
// only ever sends "pending" in the first place.
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
	if body.State != core.AccessRequestPending {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state must be \"pending\" -- a new access request is never created pre-resolved")
		return
	}
	// G80 documented-exception re-verification sweep (2026-08-25): a
	// newly-created request is always pending, so ResolvedBy has no legitimate
	// value yet — force it to zero rather than trust whatever the wire sent.
	model := body.toModel()
	model.ResolvedBy = 0
	created, err := h.coreService.Storage().CreateAccessRequest(r.Context(), model)
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
// AR-001: every legitimate caller of storage.UpdateAccessRequest
// (ApproveAccessRequestWithExpiry/RejectAccessRequest/WithdrawAccessRequest/
// ApproveSecretAccessRequest/the lazy-expiry paths in internal/core/
// invitations.go and classification_gate.go) only ever mutates State,
// GrantedRole, Reason, ResolvedBy, and ResolvedAt on the row it already
// fetched — never ProjectID/UserID/SuggestedRole/SecretID/ExpiresAt/
// CreatedAt, which are set once at creation and otherwise immutable. Because
// the underlying storage call is a `Select("*")` full-row update (same
// pattern as UpdateAccessReviewCampaign, see access_review_campaigns_proxy.go's
// package doc), a client-supplied wire body could otherwise rewrite a
// request's project/user/role identity under cover of a resolution-state
// transition. Re-fetch the authoritative row and apply only the five
// legitimate transition fields from the wire.
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
	existing, err := h.coreService.Storage().GetAccessRequest(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access request not found")
			return
		}
		log.Printf("access-requests proxy: update lookup failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	// #1529-shape guard: approving is the one transition that grants something
	// (secret-scoped: read access, the instant the row reads State=approved --
	// see ApproveSecretAccessRequest's package doc; project/role-scoped: the
	// GrantedRole record a later AssignRoleWithExpiryProxy call relies on being
	// trustworthy). Before this fix, a caller could PUT {state:"approved",
	// resolved_by:self} on an existing pending request with NO check at all --
	// same finding as CreateAccessRequestProxy above, applied to an update
	// instead of a create. Re-derive, at the hub, exactly the ceiling the
	// matching core method already applies before ever reaching this storage
	// primitive locally: maker≠checker, then admin authority (secret-scoped,
	// mirroring ApproveSecretAccessRequest) or role-grant authority
	// (project/role-scoped, mirroring ApproveAccessRequestWithExpiry's
	// RequireAuthorityForRole call). Reject/withdraw/expire are left as before:
	// core.RejectAccessRequest has no actor-authority check of its own (any
	// project member may reject), and core.WithdrawAccessRequest's self-only
	// check has no wire-carried actor field distinct from ResolvedBy to
	// re-derive against here -- out of scope for this fix.
	//
	// Wire-actor-identity finding (independent verification session, 2026-08-25):
	// the checks below used to run against body.ResolvedBy -- a caller-supplied
	// wire field -- rather than the AUTHENTICATED caller. A caller holding only
	// system.write, naming a real admin's user ID as resolved_by, cleared both
	// the self-approval check (they aren't the requester) and the admin-authority
	// check (the NAMED admin genuinely has authority) without that admin ever
	// making the call -- an approval forged in the record as someone else's
	// decision. requestActorKindAndID(r) resolves the real caller instead;
	// RequireAdminAuthorityAt/RequireAuthorityForRole are user-scoped checks
	// (internal/core/authz.go's scopedRoleIDs walks user role grants only), so a
	// machine actor's resolverID is always 0 here and correctly never passes --
	// approving dual-control access is a human-only decision, not something
	// ADR-085 changed.
	resolverType, resolverID := requestActorKindAndID(r)
	switch body.State {
	case core.AccessRequestApproved:
		if resolverType == core.ActorTypeUser && resolverID == existing.UserID {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "a requester cannot approve their own access request")
			return
		}
		if existing.SecretID != nil {
			if err := h.coreService.RequireAdminAuthorityAt(r.Context(), resolverID, existing.ProjectID); err != nil {
				writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "only an administrator can approve access to a restricted secret: "+err.Error())
				return
			}
		} else {
			role := body.GrantedRole
			if role == "" {
				role = existing.SuggestedRole
			}
			roleModel, roleErr := h.coreService.Storage().GetRoleByName(r.Context(), role)
			if roleErr != nil {
				writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "unknown role: "+roleErr.Error())
				return
			}
			if err := h.coreService.RequireGranterHoldsRolePermissions(r.Context(), resolverID, roleModel.ID, core.Scope{ProjectID: existing.ProjectID}, resolverType == core.ActorTypeMachine); err != nil {
				writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
				return
			}
		}
	case core.AccessRequestWithdrawn:
		// Mirrors core.WithdrawAccessRequest's own self-only check exactly,
		// including its "not found" (not "forbidden") classification -- a
		// non-owner must not be able to distinguish "this request doesn't
		// exist" from "it exists but isn't yours to withdraw" via this proxy
		// any more than the human-facing WithdrawAccessRequest allows.
		if resolverType != core.ActorTypeUser || resolverID != existing.UserID {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access request not found")
			return
		}
	case core.AccessRequestRejected, core.AccessRequestExpired:
		// Mirrors the local human-facing reject path's router-level gate
		// (RequireScopedPermission(permRolesAssign, projectScope) ahead of
		// core.RejectAccessRequest, which has no authority check of its own)
		// -- this proxy bypasses that router entirely, so it must re-derive
		// the same ceiling before writing. "expired" has no direct
		// client-facing equivalent at all (locally only set as a side effect
		// of internal lazy-TTL-expiry logic); held to the same roles.assign
		// ceiling as reject rather than left unchecked, since forcing a
		// request into either terminal state is the same governance action.
		if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), resolverType, resolverID, "roles.assign", core.Scope{ProjectID: existing.ProjectID}); aerr != nil || !ok {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "roles.assign is required at this request's project to reject or expire it")
			return
		}
	}
	existing.State = body.State
	existing.GrantedRole = body.GrantedRole
	existing.Reason = body.Reason
	// ResolvedBy is now always the AUTHENTICATED caller, never the wire-supplied
	// value -- see the finding above. A machine actor's resolverID (0) is a
	// pre-existing, unrelated limitation of core.AccessRequest.ResolvedBy's
	// uint-only shape (it can't distinguish "no resolver" from "machine
	// resolver 0" either way); not something this fix changes.
	existing.ResolvedBy = resolverID
	existing.ResolvedAt = body.ResolvedAt
	updated, err := h.coreService.Storage().UpdateAccessRequest(r.Context(), existing)
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
//
// G80 documented-exception re-verification sweep (2026-08-25): approver_id
// used to come straight off the wire with no relation to the authenticated
// caller. Because the uniqueness constraint is keyed on (request_id,
// approver_id), a single system.write holder could POST N approvals with N
// fabricated approver_ids and drive ApprovalsReceived past RequiredApprovals
// (internal/core/invitations.go) with zero real, independent approvers — a
// full dual-control/maker-checker bypass (A.5.3). Fixed the same way as
// CreateInvitationProxy/UpdateAccessRequestProxy: the approver is now always
// the authenticated caller, so each distinct approval row now requires a
// distinct real caller. This does not add a permission ceiling on who may
// approve at all (there was none before either) — that is a separate,
// still-open gap, out of this fix's scope.
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
	approverType, approverID := requestActorKindAndID(r)
	if approverID == 0 {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "approver_id must identify an attributable, authenticated caller")
		return
	}
	// #1642-shape ceiling gap, closed the same way UpdateAccessRequestProxy's
	// approve branch already is: re-derive maker!=checker plus the same
	// authority ceiling core.ApproveAccessRequestWithExpiry applies before an
	// approval is ever recorded, since this is an independent, storage-bypass
	// write into the SAME access_request_approvals table the hub's own
	// dual-control threshold count reads. Without this, a caller could plant
	// a phantom approval vote (diluting a K-of-N dual-control threshold) or
	// self-approve their own request (the maker!=checker check never running).
	existing, err := h.coreService.Storage().GetAccessRequest(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "access request not found")
			return
		}
		log.Printf("access-requests proxy: create approval lookup failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	if approverType == core.ActorTypeUser && approverID == existing.UserID {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "a requester cannot approve their own access request")
		return
	}
	if existing.SecretID != nil {
		if err := h.coreService.RequireAdminAuthorityAt(r.Context(), approverID, existing.ProjectID); err != nil {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", "only an administrator can approve access to a restricted secret: "+err.Error())
			return
		}
	} else {
		role := existing.GrantedRole
		if role == "" {
			role = existing.SuggestedRole
		}
		roleModel, roleErr := h.coreService.Storage().GetRoleByName(r.Context(), role)
		if roleErr != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "unknown role: "+roleErr.Error())
			return
		}
		if err := h.coreService.RequireGranterHoldsRolePermissions(r.Context(), approverID, roleModel.ID, core.Scope{ProjectID: existing.ProjectID}, approverType == core.ActorTypeMachine); err != nil {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
	}
	approval := &models.AccessRequestApproval{
		RequestID:  uint(id),
		ApproverID: approverID,
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
