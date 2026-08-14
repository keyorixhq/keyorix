// project_memberships_proxy.go — server-side endpoints backing RemoteStorage's
// CreateProjectMembership/GetProjectMembership/UpdateProjectMembership/
// ListProjectMemberships/GetActiveProjectMembership/ListStaleInvitedMemberships/
// ListUserProjectMemberships/CountProjectMembershipsByUsers (#511).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its project-membership storage calls to whichever upstream server it's
// configured against, through these eight routes (registered in
// server/http/router.go under /api/v1/system/project-memberships, gated on the
// existing system.read/system.write RBAC permissions — the SAME credential a
// RemoteStorage client already needs for every other proxied call, e.g. full user
// CRUD, project-invitation CRUD (#507), so this introduces no new privilege
// class). This mirrors invitations_proxy.go (#507) and login_attempts_proxy.go
// exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/membership_lifecycle.go already uses against a local backend — no
// membership-lifecycle POLICY decision (which state a new invite starts in, which
// transitions are legal, when the backing role grant is applied/reverted) is made
// here; that stays entirely in the CALLING server's own internal/core.KeyorixCore.
//
// Response envelope: like invitations_proxy.go/login_attempts_proxy.go, these do
// NOT use the package's generic sendSuccess/sendError helpers — they construct the
// exact {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// membershipProxyWire mirrors models.ProjectMembership's fields exactly
// (snake_case) — the wire shape internal/storage/store/remote_memberships.go's
// membershipWire sends/expects. See invitationProxyWire's comment for why every
// field is named explicitly rather than relying on encoding/json's
// case-insensitive fallback.
type membershipProxyWire struct {
	ID          uint       `json:"id"`
	ProjectID   uint       `json:"project_id"`
	UserID      uint       `json:"user_id"`
	Role        string     `json:"role"`
	State       string     `json:"state"`
	InvitedBy   uint       `json:"invited_by"`
	InvitedAt   time.Time  `json:"invited_at"`
	ActivatedAt *time.Time `json:"activated_at"`
	RevokedAt   *time.Time `json:"revoked_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

func newMembershipProxyWire(m *models.ProjectMembership) membershipProxyWire {
	return membershipProxyWire{
		ID:          m.ID,
		ProjectID:   m.ProjectID,
		UserID:      m.UserID,
		Role:        m.Role,
		State:       m.State,
		InvitedBy:   m.InvitedBy,
		InvitedAt:   m.InvitedAt,
		ActivatedAt: m.ActivatedAt,
		RevokedAt:   m.RevokedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func (w membershipProxyWire) toModel() *models.ProjectMembership {
	return &models.ProjectMembership{
		ID:          w.ID,
		ProjectID:   w.ProjectID,
		UserID:      w.UserID,
		Role:        w.Role,
		State:       w.State,
		InvitedBy:   w.InvitedBy,
		InvitedAt:   w.InvitedAt,
		ActivatedAt: w.ActivatedAt,
		RevokedAt:   w.RevokedAt,
		UpdatedAt:   w.UpdatedAt,
	}
}

// duplicateActiveMembershipCode is the machine-readable error code returned when
// storage.CreateProjectMembership fails with storage.ErrDuplicateActiveMembership
// (the upstream's own DB-level partial-unique-index rejection, #309,
// local_memberships.go) — matches remote_memberships.go's
// duplicateActiveMembershipCode constant, the wire contract the RemoteStorage
// client checks for to reconstruct the sentinel client-side.
const duplicateActiveMembershipCode = "DUPLICATE_ACTIVE_MEMBERSHIP"

// CreateMembershipProxy handles POST /api/v1/system/project-memberships. See the
// package doc for why this persists the caller's already-fully-built membership
// row as-is (a raw storage-layer create), not a re-run of
// InviteMember/inviteMemberWithMode's business logic.
func (h *CatalogHandler) CreateMembershipProxy(w http.ResponseWriter, r *http.Request) {
	var body membershipProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.ProjectID == 0 || body.UserID == 0 || body.Role == "" || body.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id, user_id, role, and state are required")
		return
	}
	created, err := h.coreService.Storage().CreateProjectMembership(r.Context(), body.toModel())
	if err != nil {
		if errors.Is(err, coreStorage.ErrDuplicateActiveMembership) {
			writeRemoteAPIError(w, http.StatusConflict, duplicateActiveMembershipCode, coreStorage.ErrDuplicateActiveMembership.Error())
			return
		}
		log.Printf("project-memberships proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMembershipProxyWire(created))
}

// GetMembershipProxy handles GET /api/v1/system/project-memberships/{id}.
func (h *CatalogHandler) GetMembershipProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid membership ID")
		return
	}
	m, err := h.coreService.Storage().GetProjectMembership(r.Context(), uint(id))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "membership not found")
			return
		}
		log.Printf("project-memberships proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMembershipProxyWire(m))
}

// UpdateMembershipProxy handles PUT /api/v1/system/project-memberships/{id}. This
// is a raw passthrough onto storage.UpdateProjectMembership (local_memberships.go's
// plain Save). #G42: this must NEVER be used for a state-machine transition
// (State/ActivatedAt/RevokedAt) — the calling core.KeyorixCore's canTransition
// legality check running before this is invoked does NOT close the TOCTOU a
// concurrent transition on the same membership races; see
// TransitionMembershipProxy below, which exists specifically for that.
func (h *CatalogHandler) UpdateMembershipProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid membership ID")
		return
	}
	var body membershipProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	if err := h.coreService.Storage().UpdateProjectMembership(r.Context(), body.toModel()); err != nil {
		log.Printf("project-memberships proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"updated": true})
}

// TransitionMembershipProxy handles PUT
// /api/v1/system/project-memberships/{id}/transition — the server-side
// endpoint backing RemoteStorage.TransitionProjectMembershipState (#G42).
// Persists the membership's full row via a single conditional UPDATE, gated
// on the row's CURRENT state still matching the request's from_state, so a
// concurrent transition on the same membership can't be silently reverted
// (or silently revert this one) across the HTTP hop the way UpdateMembershipProxy
// could.
func (h *CatalogHandler) TransitionMembershipProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid membership ID")
		return
	}
	var body struct {
		Membership membershipProxyWire `json:"membership"`
		FromState  string              `json:"from_state"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.FromState == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "from_state is required")
		return
	}
	body.Membership.ID = uint(id)
	matched, err := h.coreService.Storage().TransitionProjectMembershipState(r.Context(), body.Membership.toModel(), body.FromState)
	if err != nil {
		log.Printf("project-memberships proxy: transition failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": matched})
}

// ListMembershipsProxy handles GET /api/v1/system/project-memberships?project_id=X.
func (h *CatalogHandler) ListMembershipsProxy(w http.ResponseWriter, r *http.Request) {
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
	rows, err := h.coreService.Storage().ListProjectMemberships(r.Context(), uint(projectID))
	if err != nil {
		log.Printf("project-memberships proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, membershipListWire(rows))
}

// GetActiveMembershipProxy handles GET
// /api/v1/system/project-memberships/active?project_id=X&user_id=Y — the read
// inviteMemberWithMode uses to reject a duplicate onboarding (#309). Registered
// BEFORE the general /project-memberships/{id} pattern would ever shadow it: chi's
// router matches this literal "active" segment in preference to the {id} wildcard
// regardless of registration order (static routes always win), the same way
// /project-memberships/stale, /project-memberships/counts, and
// /project-memberships/by-user/{userID} below coexist with /project-memberships/{id}.
func (h *CatalogHandler) GetActiveMembershipProxy(w http.ResponseWriter, r *http.Request) {
	projectIDStr := r.URL.Query().Get("project_id")
	userIDStr := r.URL.Query().Get("user_id")
	if projectIDStr == "" || userIDStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id and user_id query parameters are required")
		return
	}
	projectID, err := strconv.ParseUint(projectIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return
	}
	userID, err := strconv.ParseUint(userIDStr, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_id must be a valid integer")
		return
	}
	m, err := h.coreService.Storage().GetActiveProjectMembership(r.Context(), uint(projectID), uint(userID))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "no active membership for this project and user")
			return
		}
		log.Printf("project-memberships proxy: get active failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newMembershipProxyWire(m))
}

// ListStaleInvitedMembershipsProxy handles GET
// /api/v1/system/project-memberships/stale?before=<RFC3339Nano> (ADR-022
// stale-invite warnings).
func (h *CatalogHandler) ListStaleInvitedMembershipsProxy(w http.ResponseWriter, r *http.Request) {
	beforeStr := r.URL.Query().Get("before")
	if beforeStr == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "before query parameter is required")
		return
	}
	before, err := time.Parse(time.RFC3339Nano, beforeStr)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "before must be an RFC3339 timestamp")
		return
	}
	rows, err := h.coreService.Storage().ListStaleInvitedMemberships(r.Context(), before)
	if err != nil {
		log.Printf("project-memberships proxy: list stale failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, membershipListWire(rows))
}

// ListUserMembershipsProxy handles GET
// /api/v1/system/project-memberships/by-user/{userID} (ADR-025 per-user
// assignments view).
func (h *CatalogHandler) ListUserMembershipsProxy(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "userID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user ID")
		return
	}
	rows, err := h.coreService.Storage().ListUserProjectMemberships(r.Context(), uint(userID))
	if err != nil {
		log.Printf("project-memberships proxy: list by user failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, membershipListWire(rows))
}

// CountMembershipsByUsersProxy handles GET
// /api/v1/system/project-memberships/counts?user_ids=1,2,3 (ADR-025 user list).
func (h *CatalogHandler) CountMembershipsByUsersProxy(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("user_ids")
	if raw == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_ids query parameter is required")
		return
	}
	parts := strings.Split(raw, ",")
	userIDs := make([]uint, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "user_ids must be a comma-separated list of integers")
			return
		}
		userIDs = append(userIDs, uint(id))
	}
	counts, err := h.coreService.Storage().CountProjectMembershipsByUsers(r.Context(), userIDs)
	if err != nil {
		log.Printf("project-memberships proxy: count by users failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	// encoding/json supports unsigned-integer map keys directly (encoded as their
	// base-10 string form), matching what remote_memberships.go's
	// CountProjectMembershipsByUsers unmarshals into — no wire-shape translation
	// needed here.
	writeRemoteAPISuccess(w, counts)
}

// membershipListWire converts a slice of models.ProjectMembership into the
// {"memberships": [...]} envelope remote_memberships.go's decodeMembershipList
// expects.
func membershipListWire(rows []*models.ProjectMembership) map[string]interface{} {
	wire := make([]membershipProxyWire, 0, len(rows))
	for _, m := range rows {
		wire = append(wire, newMembershipProxyWire(m))
	}
	return map[string]interface{}{"memberships": wire}
}
