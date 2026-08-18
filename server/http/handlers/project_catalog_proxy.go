// project_catalog_proxy.go — server-side endpoints backing RemoteStorage's Project
// catalog methods (ListProjects/ListProjectsWithCounts/GetProject/UpdateProject/
// DeleteProject/DeleteProjectIfEmpty/RestoreProject/ListProjectMembers).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies its
// project-catalog storage calls to whichever upstream server it's configured against,
// through these routes (registered in server/http/router.go under
// /api/v1/system/projects*, gated on the existing system.read/system.write RBAC
// permissions — the SAME credential a RemoteStorage client already needs for every
// other proxied call, so this introduces no new privilege class). Exactly the same
// pattern as groups_proxy.go/login_attempts_proxy.go/invitations_proxy.go: thin
// passthroughs onto the SAME storage.Storage primitives
// (internal/storage/store/local_secrets.go's LocalStorage.ListProjects et al.)
// internal/core/catalog.go already uses against a local backend — NO project POLICY
// decision (name/description validation, MFA-requirement authorization, invitation/
// membership side effects, dynamic-secret-lease revocation, audit-log events, the
// requireAuthorityToReinstateProjectRoles admin-ceiling check) is made here; that
// stays entirely in the CALLING server's own internal/core.KeyorixCore, exactly as it
// does against a local backend. The existing human-facing /api/v1/projects routes
// (catalog.go) are deliberately NOT reused as the proxy target for the same reason
// groups_proxy.go's doc comment gives: they run through core.KeyorixCore, so proxying
// onto them would apply that business logic a second time, upstream, against the
// wrong actor context.
//
// DeleteProjectIfEmptyProxy is the one exception to "thin passthrough onto an
// existing local primitive": it backs storage.Storage.DeleteProjectIfEmpty, a NEW
// atomic primitive added by #528 specifically so a force=false project delete stays
// atomic (guard-count + cascade in ONE call) across the HTTP hop — see that method's
// doc comment on the storage.Storage interface for the full TOCTOU rationale. It is
// still a thin passthrough: the guard threshold (zero secrets) and the cascade itself
// are unchanged storage-layer behavior, just invoked as one call instead of two.
//
// Response envelope: like the proxies above, these do NOT use the package's generic
// sendSuccess/sendError helpers — they construct the exact
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

// projectProxyWire mirrors models.Project's fields exactly (snake_case) — the wire
// shape RemoteStorage's project methods (internal/storage/store/remote_rbac.go)
// send/expect. See groupProxyWire's comment for why every field is named explicitly
// rather than relying on encoding/json's case-insensitive fallback (models.Project
// carries no json tags of its own).
type projectProxyWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	RequireMFA  bool       `json:"require_mfa"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func newProjectProxyWire(p *models.Project) projectProxyWire {
	w := projectProxyWire{
		ID:          p.ID,
		Name:        p.Name,
		Description: p.Description,
		RequireMFA:  p.RequireMFA,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
	if p.DeletedAt.Valid {
		t := p.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

func (w projectProxyWire) toModel() *models.Project {
	p := &models.Project{
		ID:          w.ID,
		Name:        w.Name,
		Description: w.Description,
		RequireMFA:  w.RequireMFA,
		// CreatedAt/UpdatedAt/DeletedAt (#G80) — dropping these on the request
		// leg silently zeroed CreatedAt (and lost DeletedAt) on every proxied
		// update, even though the wire struct and newProjectProxyWire (the
		// response leg) already carry them correctly.
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
	if w.DeletedAt != nil {
		p.DeletedAt.Time = *w.DeletedAt
		p.DeletedAt.Valid = true
	}
	return p
}

// isProjectNotFound reports whether err is a errProjectNotFound error from
// LocalStorage (local_secrets.go's GetProject/DeleteProject/DeleteProjectIfEmpty
// cascade/RestoreProject all use this literal substring).
func isProjectNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// ListProjectsProxy handles GET /api/v1/system/projects.
func (h *CatalogHandler) ListProjectsProxy(w http.ResponseWriter, r *http.Request) {
	projects, err := h.coreService.Storage().ListProjects(r.Context())
	if err != nil {
		log.Printf("project catalog proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]projectProxyWire, 0, len(projects))
	for _, p := range projects {
		wire = append(wire, newProjectProxyWire(p))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"projects": wire})
}

// ListProjectsWithCountsProxy handles GET
// /api/v1/system/projects/with-counts?include_deleted=true.
func (h *CatalogHandler) ListProjectsWithCountsProxy(w http.ResponseWriter, r *http.Request) {
	includeDeleted := r.URL.Query().Get("include_deleted") == "true"
	projects, err := h.coreService.Storage().ListProjectsWithCounts(r.Context(), includeDeleted)
	if err != nil {
		log.Printf("project catalog proxy: list with counts failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"projects": projects})
}

// GetProjectProxy handles GET /api/v1/system/projects/{id}.
func (h *CatalogHandler) GetProjectProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	p, err := h.coreService.Storage().GetProject(r.Context(), uint(id))
	if err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errProjectNotFound)
			return
		}
		log.Printf("project catalog proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newProjectProxyWire(p))
}

// GetProjectByNameProxy handles GET /api/v1/system/projects/by-name/{name} —
// ADR-082 branch 2's boot-time connector resolution (server/main.go), proxied so a
// storage.type: remote node can resolve a connector's configured project: name
// against the upstream server's real Project table instead of RemoteStorage's
// GetProjectByName having no server endpoint to call at all.
func (h *CatalogHandler) GetProjectByNameProxy(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "name is required")
		return
	}
	p, err := h.coreService.Storage().GetProjectByName(r.Context(), name)
	if err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errProjectNotFound)
			return
		}
		log.Printf("project catalog proxy: get by name failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newProjectProxyWire(p))
}

// UpdateProjectProxy handles PUT /api/v1/system/projects/{id}. Like the group/
// invitation proxies' raw persist, this trusts the caller's already-fully-resolved
// final desired state (the calling core.KeyorixCore.UpdateProject already merged the
// existing row with the requested changes before invoking storage.UpdateProject)
// rather than re-deriving a partial update here.
func (h *CatalogHandler) UpdateProjectProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	var body projectProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	body.ID = uint(id)
	updated, err := h.coreService.Storage().UpdateProject(r.Context(), body.toModel())
	if err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errProjectNotFound)
			return
		}
		log.Printf("project catalog proxy: update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newProjectProxyWire(updated))
}

// DeleteProjectProxy handles DELETE /api/v1/system/projects/{id} — the plain,
// unconditional cascade (storage.Storage.DeleteProject), backing the CALLING
// server's force=true path. The force=false guard+cascade is DeleteProjectIfEmptyProxy
// below, not this endpoint.
func (h *CatalogHandler) DeleteProjectProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	if err := h.coreService.Storage().DeleteProject(r.Context(), uint(id)); err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errProjectNotFound)
			return
		}
		log.Printf("project catalog proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// DeleteProjectIfEmptyProxy handles POST /api/v1/system/projects/{id}/delete-if-empty
// — the atomic guard+cascade backing storage.Storage.DeleteProjectIfEmpty (#528; see
// that method's interface doc comment). Runs the whole guard-count-then-cascade
// sequence in ONE call against THIS server's real storage, so the count the guard
// rejects on is read from, and committed alongside, the same transaction as the
// cascade — closing the TOCTOU window a naive two-call (count, then delete) proxy
// would reopen across the network hop.
func (h *CatalogHandler) DeleteProjectIfEmptyProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	blocking, err := h.coreService.Storage().DeleteProjectIfEmpty(r.Context(), uint(id))
	if err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", errProjectNotFound)
			return
		}
		log.Printf("project catalog proxy: delete-if-empty failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"blocking_secret_count": blocking})
}

// RestoreProjectProxy handles POST /api/v1/system/projects/{id}/restore.
func (h *CatalogHandler) RestoreProjectProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	restoredEnvironments, restoredSecrets, err := h.coreService.Storage().RestoreProject(r.Context(), uint(id))
	if err != nil {
		if isProjectNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "project not found or not deleted")
			return
		}
		log.Printf("project catalog proxy: restore failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{
		"restored_environments": restoredEnvironments,
		"restored_secrets":      restoredSecrets,
	})
}

// ListProjectMembersProxy handles GET /api/v1/system/projects/{id}/members.
func (h *CatalogHandler) ListProjectMembersProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidProjectIDLower)
		return
	}
	members, err := h.coreService.Storage().ListProjectMembers(r.Context(), uint(id))
	if err != nil {
		log.Printf("project catalog proxy: list members failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"members": members})
}
