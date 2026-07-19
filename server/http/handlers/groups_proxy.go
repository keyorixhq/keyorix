// groups_proxy.go — server-side endpoints backing RemoteStorage's Group CRUD
// and membership methods (CreateGroup/GetGroup/UpdateGroup/DeleteGroup/
// RestoreGroup/ListGroups/ListGroupsPage/AddUserToGroup/RemoveUserFromGroup/
// ListGroupMembers/ListGroupMembersByGroupIDs/GetUserGroups).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049)
// proxies its Group storage calls to whichever upstream server it's
// configured against, through these routes (registered in
// server/http/router.go under /api/v1/system/groups and
// /api/v1/system/users/{id}/groups, gated on the existing system.read/
// system.write RBAC permissions — the SAME credential a RemoteStorage client
// already needs for every other proxied call, e.g. full user CRUD, so this
// introduces no new privilege class). This mirrors the #452-follow-up
// login-attempts proxy (login_attempts_proxy.go) and the #507
// project-invitations proxy (invitations_proxy.go) exactly.
//
// These are thin passthroughs onto the SAME storage.Storage Group primitives
// (internal/storage/store/local_users.go's LocalStorage.CreateGroup et al.)
// internal/core/groups.go already uses against a local backend — NO group
// policy decision (name/description validation, audit-log events, the
// escalation-by-proxy ceilings guardLastGlobalAdminGroupDelete/
// guardLastGlobalAdminMembership/requireGlobalAdminToReinstateAdminRoles/
// requireAuthorityForRole apply) is made here; that stays entirely in the
// CALLING server's own internal/core.KeyorixCore, exactly as it does against a
// local backend. The existing human-facing /api/v1/groups routes
// (groups_handler.go, groups_members.go) are deliberately NOT reused as the
// proxy target — see internal/storage/store/remote_users.go's package doc for
// why (they run through core.KeyorixCore, so proxying onto them would apply
// that same business logic a second time, upstream, against the wrong actor
// context).
//
// Response envelope: like login_attempts_proxy.go and invitations_proxy.go,
// these do NOT use the package's generic sendSuccess/sendError helpers — they
// construct the exact {"success":bool,"data":...,"error":{"code","message"}}
// shape internal/storage/remote.HTTPClient parses (its APIResponse/APIError
// types).
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


// groupProxyWire mirrors models.Group's fields exactly (snake_case) — the wire
// shape internal/storage/store/remote_users.go's groupWire sends/expects. See
// that type's comment for why every field is named explicitly rather than
// relying on encoding/json's case-insensitive fallback (the same #496 class of
// gap: models.Group carries no json tags of its own).
type groupProxyWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newGroupProxyWire(g *models.Group) groupProxyWire {
	w := groupProxyWire{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		CreatedAt:   g.CreatedAt,
		UpdatedAt:   g.UpdatedAt,
	}
	if g.DeletedAt.Valid {
		t := g.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

func (w groupProxyWire) toModel() *models.Group {
	return &models.Group{
		ID:          w.ID,
		Name:        w.Name,
		Description: w.Description,
	}
}

// isGroupNotFound reports whether err is LocalStorage's errGroupNotFoundLower
// error (local_users.go wraps i18n.T("ErrorGroupNotFound", ...), which does
// not necessarily contain the literal substring "not found" in every locale —
// but LocalStorage always runs with the server's configured locale, and
// RestoreGroup's own plain "group not found or not deleted" always does).
func isGroupNotFound(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") || strings.Contains(msg, "notfound")
}

// CreateGroupProxy handles POST /api/v1/system/groups.
func (h *GroupHandler) CreateGroupProxy(w http.ResponseWriter, r *http.Request) {
	var body groupProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.Name == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "name is required")
		return
	}
	created, err := h.coreService.Storage().CreateGroup(r.Context(), body.toModel())
	if err != nil {
		log.Printf("groups proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newGroupProxyWire(created))
}

// GetGroupProxy handles GET /api/v1/system/groups/{id}.
func (h *GroupHandler) GetGroupProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	g, err := h.coreService.Storage().GetGroup(r.Context(), uint(id))
	if err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errGroupNotFoundLower)
			return
		}
		log.Printf("groups proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newGroupProxyWire(g))
}

// UpdateGroupProxy handles PUT /api/v1/system/groups/{id}. Like the invitation
// proxy's raw persist, this trusts the caller's already-fully-resolved final
// desired state (the calling core.KeyorixCore.UpdateGroup already merged the
// existing row with the requested changes before invoking storage.UpdateGroup)
// rather than re-deriving a partial update here.
func (h *GroupHandler) UpdateGroupProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	var body groupProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	body.ID = uint(id)
	updated, err := h.coreService.Storage().UpdateGroup(r.Context(), body.toModel())
	if err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errGroupNotFoundLower)
			return
		}
		log.Printf("groups proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newGroupProxyWire(updated))
}

// DeleteGroupProxy handles DELETE /api/v1/system/groups/{id}. Soft-deletes the
// group (LocalStorage.DeleteGroup), preserving its role grants and
// memberships for a later RestoreGroupProxy call — identical to a local
// backend.
func (h *GroupHandler) DeleteGroupProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	if err := h.coreService.Storage().DeleteGroup(r.Context(), uint(id)); err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errGroupNotFoundLower)
			return
		}
		log.Printf("groups proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// RestoreGroupProxy handles POST /api/v1/system/groups/{id}/restore.
func (h *GroupHandler) RestoreGroupProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	if err := h.coreService.Storage().RestoreGroup(r.Context(), uint(id)); err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "group not found or not deleted")
			return
		}
		log.Printf("groups proxy: restore failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"restored": true})
}

// ListGroupsProxy handles GET /api/v1/system/groups.
func (h *GroupHandler) ListGroupsProxy(w http.ResponseWriter, r *http.Request) {
	groups, err := h.coreService.Storage().ListGroups(r.Context())
	if err != nil {
		log.Printf("groups proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]groupProxyWire, 0, len(groups))
	for _, g := range groups {
		wire = append(wire, newGroupProxyWire(g))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"groups": wire})
}

// ListGroupsPageProxy handles GET /api/v1/system/groups/page?offset=&limit=.
func (h *GroupHandler) ListGroupsPageProxy(w http.ResponseWriter, r *http.Request) {
	offset, err := strconv.Atoi(r.URL.Query().Get("offset"))
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "offset must be a valid integer")
		return
	}
	limit, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "limit must be a valid integer")
		return
	}
	groups, total, err := h.coreService.Storage().ListGroupsPage(r.Context(), offset, limit)
	if err != nil {
		log.Printf("groups proxy: list page failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]groupProxyWire, 0, len(groups))
	for _, g := range groups {
		wire = append(wire, newGroupProxyWire(g))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"groups": wire, "total": total})
}

// groupMemberBody is the wire body for POST /api/v1/system/groups/{id}/members.
// ProjectID is optional; 0 (or omitted) means a global membership.
type groupMemberBody struct {
	UserID    uint `json:"user_id"`
	ProjectID uint `json:"project_id"`
}

// AddGroupMemberProxy handles POST /api/v1/system/groups/{id}/members.
func (h *GroupHandler) AddGroupMemberProxy(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	var body groupMemberBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id is required")
		return
	}
	if err := h.coreService.Storage().AddUserToGroup(r.Context(), body.UserID, uint(groupID), body.ProjectID); err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "user or group not found")
			return
		}
		log.Printf("groups proxy: add member failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"added": true})
}

// RemoveGroupMemberProxy handles DELETE /api/v1/system/groups/{id}/members/{userId}.
// Optional query param: project_id (default 0 = global membership).
func (h *GroupHandler) RemoveGroupMemberProxy(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	userID, err := strconv.ParseUint(chi.URLParam(r, "userId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user ID")
		return
	}
	var projectID uint
	if pidStr := r.URL.Query().Get("project_id"); pidStr != "" {
		pid, parseErr := strconv.ParseUint(pidStr, 10, 32)
		if parseErr != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid project_id")
			return
		}
		projectID = uint(pid)
	}
	if err := h.coreService.Storage().RemoveUserFromGroup(r.Context(), uint(userID), uint(groupID), projectID); err != nil {
		log.Printf("groups proxy: remove member failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"removed": true})
}

// ListGroupMembersProxy handles GET /api/v1/system/groups/{id}/members.
func (h *GroupHandler) ListGroupMembersProxy(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidGroupIDLower)
		return
	}
	members, err := h.coreService.Storage().ListGroupMembers(r.Context(), uint(groupID))
	if err != nil {
		if isGroupNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errGroupNotFoundLower)
			return
		}
		log.Printf("groups proxy: list members failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	out := make([]map[string]interface{}, 0, len(members))
	for _, u := range members {
		out = append(out, userToAPIResponse(u))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"members": out})
}

// ListGroupMembersByIDsProxy handles GET
// /api/v1/system/groups/members-by-ids?ids=1,2,3 — the batch form of
// ListGroupMembersProxy (used by the rotation planner's risk-scoring batch,
// #409).
func (h *GroupHandler) ListGroupMembersByIDsProxy(w http.ResponseWriter, r *http.Request) {
	idsParam := r.URL.Query().Get("ids")
	if idsParam == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "ids query parameter is required")
		return
	}
	parts := strings.Split(idsParam, ",")
	groupIDs := make([]uint, 0, len(parts))
	for _, p := range parts {
		id, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "ids must be a comma-separated list of integers")
			return
		}
		groupIDs = append(groupIDs, uint(id))
	}
	byGroup, err := h.coreService.Storage().ListGroupMembersByGroupIDs(r.Context(), groupIDs)
	if err != nil {
		log.Printf("groups proxy: list members by IDs failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	out := make(map[string]interface{}, len(byGroup))
	for groupID, members := range byGroup {
		wire := make([]map[string]interface{}, 0, len(members))
		for _, u := range members {
			wire = append(wire, userToAPIResponse(u))
		}
		out[strconv.FormatUint(uint64(groupID), 10)] = wire
	}
	writeRemoteAPISuccess(w, out)
}

// GetUserGroupsProxy handles GET /api/v1/system/users/{id}/groups.
func (h *GroupHandler) GetUserGroupsProxy(w http.ResponseWriter, r *http.Request) {
	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid user ID")
		return
	}
	groups, err := h.coreService.Storage().GetUserGroups(r.Context(), uint(userID))
	if err != nil {
		log.Printf("groups proxy: get user groups failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]groupProxyWire, 0, len(groups))
	for _, g := range groups {
		wire = append(wire, newGroupProxyWire(g))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"groups": wire})
}
