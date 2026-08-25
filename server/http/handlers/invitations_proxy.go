// invitations_proxy.go — server-side endpoints backing RemoteStorage's
// CreateProjectInvitation/GetProjectInvitation/UpdateProjectInvitation/
// ListProjectInvitations (#507).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its project-invitation storage calls to whichever upstream server it's
// configured against, through these four routes (registered in
// server/http/router.go under /api/v1/system/invitations, gated on the existing
// system.read/system.write RBAC permissions — the SAME credential a RemoteStorage
// client already needs for every other proxied call, e.g. full user CRUD, so this
// introduces no new privilege class). This mirrors the #452-follow-up
// login-attempts proxy (login_attempts_proxy.go) exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// (CreateProjectInvitation/GetProjectInvitation/UpdateProjectInvitation/
// ListProjectInvitations) internal/core/invitations.go and setup_consume.go
// already use against a local backend — no invitation POLICY decision
// (escalation-by-proxy checks, TTLs, which transitions are legal) is made here;
// that stays entirely in the CALLING server's own internal/core.KeyorixCore.
// Crucially, UpdateProjectInvitationProxy calls storage.UpdateProjectInvitation
// directly, so it inherits local_invitations.go's conditional
// `WHERE id = ? AND state = 'pending'` write verbatim — the single-use-accept
// race guarantee setup_consume.go's completeInvitationAccept depends on survives
// this HTTP hop unchanged; there is no separate "check pending, then write"
// sequence here to reintroduce that TOCTOU.
//
// Response envelope: like login_attempts_proxy.go, these do NOT use the package's
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

// invitationProxyWire mirrors models.ProjectInvitation's fields exactly
// (snake_case) — the wire shape internal/storage/store/remote_invitations.go's
// invitationWire sends/expects. See that type's comment for why every field is
// named explicitly rather than relying on encoding/json's case-insensitive
// fallback (the same #496 class of gap: models.ProjectInvitation carries no json
// tags of its own).
type invitationProxyWire struct {
	ID                     uint       `json:"id"`
	ProjectID              uint       `json:"project_id"`
	Email                  string     `json:"email"`
	Role                   string     `json:"role"`
	State                  string     `json:"state"`
	InvitedBy              uint       `json:"invited_by"`
	ValidationModeAtInvite string     `json:"validation_mode_at_invite"`
	SystemRole             string     `json:"system_role"`
	AssignmentsJSON        string     `json:"assignments_json"`
	ExpiresAt              *time.Time `json:"expires_at"`
	CreatedAt              time.Time  `json:"created_at"`
	AcceptedAt             *time.Time `json:"accepted_at"`
	RevokedAt              *time.Time `json:"revoked_at"`
}

func newInvitationProxyWire(inv *models.ProjectInvitation) invitationProxyWire {
	return invitationProxyWire{
		ID:                     inv.ID,
		ProjectID:              inv.ProjectID,
		Email:                  inv.Email,
		Role:                   inv.Role,
		State:                  inv.State,
		InvitedBy:              inv.InvitedBy,
		ValidationModeAtInvite: inv.ValidationModeAtInvite,
		SystemRole:             inv.SystemRole,
		AssignmentsJSON:        inv.AssignmentsJSON,
		ExpiresAt:              inv.ExpiresAt,
		CreatedAt:              inv.CreatedAt,
		AcceptedAt:             inv.AcceptedAt,
		RevokedAt:              inv.RevokedAt,
	}
}

func (w invitationProxyWire) toModel() *models.ProjectInvitation {
	return &models.ProjectInvitation{
		ID:                     w.ID,
		ProjectID:              w.ProjectID,
		Email:                  w.Email,
		Role:                   w.Role,
		State:                  w.State,
		InvitedBy:              w.InvitedBy,
		ValidationModeAtInvite: w.ValidationModeAtInvite,
		SystemRole:             w.SystemRole,
		AssignmentsJSON:        w.AssignmentsJSON,
		ExpiresAt:              w.ExpiresAt,
		CreatedAt:              w.CreatedAt,
		AcceptedAt:             w.AcceptedAt,
		RevokedAt:              w.RevokedAt,
	}
}

// validInvitationTargetState reports whether s is a state this proxy may WRITE.
// "pending" is deliberately excluded — it is only ever the initial state a
// CreateProjectInvitation persists, never a target of an UPDATE (every real
// transition in internal/core/invitations.go and setup_consume.go moves AWAY
// from pending), so accepting it here would let a caller resurrect an already
// resolved invitation back to pending instead of merely transitioning it forward.
func validInvitationTargetState(s string) bool {
	switch s {
	case "accepted", "revoked", "expired":
		return true
	default:
		return false
	}
}

// CreateInvitationProxy handles POST /api/v1/system/invitations. See the package
// doc for why this persists the caller's already-fully-built invitation as-is
// (a raw storage-layer create) rather than routing through
// InviteToProject/InviteToProjectWithLink's business logic + email delivery a
// second time.
//
// #1529-shape guard: InviteToProject/InviteGlobal both call
// requireAuthorityForRole before ever persisting -- a system.write-only caller
// (no project-admin authority) must not be able to mint a pending admin-role
// invitation by relaying a raw create with no upstream check having actually
// run. Re-derive, at the hub, the SAME escalation-by-proxy ceiling for every
// role this wire body can carry: the project-scoped Role, the global
// SystemRole, and each project assignment bundled into AssignmentsJSON --
// exactly the three checks InviteToProject/InviteGlobal apply before ever
// reaching this storage primitive locally.
func (h *CatalogHandler) CreateInvitationProxy(w http.ResponseWriter, r *http.Request) {
	var body invitationProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.ProjectID == 0 && body.SystemRole == "" && body.AssignmentsJSON == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id is required for a project-scoped invitation")
		return
	}
	if body.Email == "" || body.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "email and state are required")
		return
	}
	// Wire-actor-identity finding (independent verification session, 2026-08-25):
	// these three checks used to run against body.InvitedBy -- a caller-supplied
	// wire field -- rather than the AUTHENTICATED caller. A caller holding only
	// system.write, naming a real admin's user ID as invited_by, cleared every
	// one of these RequireAuthorityForRole checks (the NAMED admin genuinely has
	// authority) without that admin ever making the call -- one request planted
	// a live, pending system_admin invitation to an attacker-controlled email,
	// falsely attributed in the record to a real administrator. actorID(r)
	// resolves the real caller instead; RequireAuthorityForRole is a
	// user-scoped check (internal/core/authz.go's scopedRoleIDs walks user role
	// grants only), so a machine actor's actorID(r) is always 0 here and
	// correctly never passes -- inviting someone is a human-only decision.
	if body.Role != "" {
		if err := h.coreService.RequireAuthorityForRole(r.Context(), actorID(r), body.ProjectID, body.Role); err != nil {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
	}
	if body.SystemRole != "" {
		if err := h.coreService.RequireAuthorityForRole(r.Context(), actorID(r), 0, body.SystemRole); err != nil {
			writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
			return
		}
	}
	if body.AssignmentsJSON != "" {
		var assignments []core.ProjectAssignment
		if err := json.Unmarshal([]byte(body.AssignmentsJSON), &assignments); err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "assignments_json is not a valid assignment list")
			return
		}
		for _, a := range assignments {
			if err := h.coreService.RequireAuthorityForRole(r.Context(), actorID(r), a.ProjectID, a.Role); err != nil {
				writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
				return
			}
		}
	}
	model := body.toModel()
	// InvitedBy is now always the AUTHENTICATED caller, never the wire-supplied
	// value -- see the finding above.
	model.InvitedBy = actorID(r)
	created, err := h.coreService.Storage().CreateProjectInvitation(r.Context(), model)
	if err != nil {
		log.Printf("invitations proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newInvitationProxyWire(created))
}

// GetInvitationProxy handles GET /api/v1/system/invitations/{id}.
func (h *CatalogHandler) GetInvitationProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid invitation ID")
		return
	}
	inv, err := h.coreService.Storage().GetProjectInvitation(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "invitation not found")
			return
		}
		log.Printf("invitations proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newInvitationProxyWire(inv))
}

// UpdateInvitationProxy handles PUT /api/v1/system/invitations/{id}. It performs
// the SAME conditional `WHERE id = ? AND state = 'pending'` write LocalStorage's
// own UpdateProjectInvitation does (h.coreService.Storage() reaches the identical
// storage.Storage primitive this server's local /auth/setup/consume and
// /projects/{id}/invitations paths use), returning whether it actually matched a
// still-pending row — the single round trip a concurrent-accept race resolves in.
//
// #1529-shape guard: every legitimate caller of storage.UpdateProjectInvitation
// (completeInvitationAccept/RevokeInvitation/expireInvitationIfOverdue, all in
// internal/core) re-fetches the row it already has and mutates ONLY State plus
// AcceptedAt (accept) or RevokedAt (revoke) — never Email/Role/InvitedBy/
// SystemRole/AssignmentsJSON/ProjectID, which are set once at creation and
// otherwise immutable. Because the underlying storage call is a `Select("*")`
// full-row update (same AR-001 pattern as UpdateAccessRequestProxy), a
// client-supplied wire body could otherwise rewrite an invitation's identity
// (e.g. SystemRole) under cover of a resolution-state transition, or force
// State=accepted on a row with no grant ever applied on this side, stranding
// the real invitee (completeInvitationAccept's own pending check then refuses
// them with "invitation is accepted"). Re-fetch the authoritative row and apply
// only the legitimate transition fields from the wire, matching every real
// caller's own behavior exactly.
func (h *CatalogHandler) UpdateInvitationProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid invitation ID")
		return
	}
	var body invitationProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if !validInvitationTargetState(body.State) {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "state must be one of accepted, revoked, expired")
		return
	}
	existing, err := h.coreService.Storage().GetProjectInvitation(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "invitation not found")
			return
		}
		log.Printf("invitations proxy: update lookup failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	existing.State = body.State
	existing.AcceptedAt = body.AcceptedAt
	existing.RevokedAt = body.RevokedAt
	updated, err := h.coreService.Storage().UpdateProjectInvitation(r.Context(), existing)
	if err != nil {
		log.Printf("invitations proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": updated})
}

// ListInvitationsProxy handles GET /api/v1/system/invitations?project_id=X.
func (h *CatalogHandler) ListInvitationsProxy(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.coreService.Storage().ListProjectInvitations(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("invitations proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]invitationProxyWire, 0, len(rows))
	for _, inv := range rows {
		wire = append(wire, newInvitationProxyWire(inv))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"invitations": wire})
}
