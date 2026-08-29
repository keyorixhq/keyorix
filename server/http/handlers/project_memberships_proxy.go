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
	"github.com/keyorixhq/keyorix/internal/core"
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
	// #1578: this used to persist an arbitrary Role straight from the wire —
	// the human-facing path (inviteMemberWithMode, membership_lifecycle.go)
	// gates an admin-tier grant on RequireAuthorityForRole before it ever
	// reaches storage; this proxy skipped that gate entirely, so any
	// system.write-only caller (the RemoteStorage federation credential, not
	// a project-admin credential) could mint itself or anyone else an
	// admin-tier active membership. Derive the same ceiling the human-facing
	// path uses, by reference, rather than re-deriving an equivalent check.
	if err := h.coreService.RequireAuthorityForRole(r.Context(), actorID(r), body.ProjectID, body.Role); err != nil {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}
	// G80 documented-exception re-verification sweep (2026-08-25): InvitedBy
	// used to persist verbatim from the wire — forgeable attribution that
	// feeds notification routing (internal/core/notifications.go) and the
	// audit trail. Force it to the authenticated caller.
	model := body.toModel()
	model.InvitedBy = actorID(r)
	created, err := h.coreService.Storage().CreateProjectMembership(r.Context(), model)
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

// UpdateMembershipProxy was DELETED (#1586, docs/adr-090-stale-fork-proxy-deletion.md):
// a raw passthrough onto storage.UpdateProjectMembership (local_memberships.go's
// plain Save) reproducing the exact TOCTOU TransitionProjectMembershipState
// was rewritten to close (#G42) — the adjacent TransitionMembershipProxy's own
// doc comment named this exact route as the race it was built to avoid. A
// repo-wide liveness check found ZERO callers of storage.UpdateProjectMembership
// anywhere in internal/core, and no CLI command surface for project
// memberships at all: nothing calls this raw primitive under any topology.
// See the ADR for the full liveness chain. TransitionMembershipProxy below is
// the safe route and is unaffected.

// TransitionMembershipProxy handles PUT
// /api/v1/system/project-memberships/{id}/transition — the server-side
// endpoint backing RemoteStorage.TransitionProjectMembershipState (#G42).
//
// #1546: routes through core.TransitionMembership (FULL delegation) rather
// than the narrow-primitive bolt-on ADR-088 costed for this handler
// (docs/adr-088-system-proxy-layer-design.md, "Costing the rule against
// #1546/#1551/#1572"). That costing assumed a live spoke already runs
// core.TransitionMembership locally before relaying here, so full
// delegation would duplicate the role-grant side effect
// (AddProjectMember/RemoveProjectMember) the spoke already applied.
// Liveness tracing for #1546 found no such spoke: core.TransitionMembership
// has exactly one caller repo-wide (server/http/handlers/project_memberships.go,
// the human-facing route, reachable only inside a booted HTTP server) and no
// server process can ever run storage.type: remote
// (validateRemoteStorageNotServer, internal/config/config.go, unconditional
// since #1549) — so no spoke server can exist. No CLI command calls
// core.TransitionMembership either (no project-membership CLI surface
// exists at all). ADR-088's rule is explicitly conditional on that spoke
// executing core locally ("Precondition this rule depends on" section); the
// precondition does not hold for this specific handler, so the rule's
// conclusion (bolt-on beats delegation) does not transfer to it either —
// re-derived here, not inherited.
//
// Full delegation closes more than the ceiling+side-effect gap #1546 named:
// the OLD raw-write version persisted the wire's ENTIRE membership row
// verbatim (role, user_id, invited_by, ...) via body.Membership.toModel(),
// so a caller could rewrite a membership's role while nominally just
// "transitioning" it. core.TransitionMembership reads its OWN authoritative
// row and only accepts (projectID, membershipID, to, actorID) from the
// caller -- every other field is now ignored on the wire, closing that
// forgery surface too. It also applies canTransition's state-machine
// legality check, which the raw write never did (any from_state/to pair the
// wire claimed would persist as long as the CAS condition matched).
//
// actorID is resolved from the authenticated caller (actorID(r)), never the
// wire body — same convention CreateMembershipProxy's own #1578 fix uses
// immediately above.
//
// Wire-shape note: from_state is still accepted (unchanged request shape
// for whatever, if anything, sends it) but deliberately unused --
// core.TransitionMembership re-derives the current state itself from a
// fresh read rather than trusting the wire's claim, so a stale or forged
// from_state can no longer influence the outcome the way it could in the
// raw-write version (there, it was the ENTIRE CAS gate).
//
// Not replicated: core.TransitionMembership's own best-effort
// revertFailedActivation (reverting the state row if the role-grant side
// effect fails AFTER the CAS write already committed) is unexported and
// internal to internal/core -- exporting it to reach it from this handler
// would grow this fix past a single handler's worth of change. That failure
// mode surfaces to the caller as a genuine error (STORAGE_ERROR) either
// way; the row is left in its new state with the role grant not applied,
// same residual risk core's own local callers already accept, just without
// the auto-revert. Stated here as a residual gap, not silently dropped.
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
	if body.Membership.State == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "membership.state (the target state) is required")
		return
	}
	_, err = h.coreService.TransitionMembership(r.Context(), body.Membership.ProjectID, uint(id), body.Membership.State, actorID(r))
	if err != nil {
		// #G42: a lost CAS race is a normal outcome on this wire contract
		// (matched=false), not a server error -- matches every other
		// conditional-transition wire method in this package.
		if errors.Is(err, core.ErrMembershipStateConflict) {
			writeRemoteAPISuccess(w, map[string]bool{"matched": false})
			return
		}
		log.Printf("project-memberships proxy: transition failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"matched": true})
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
