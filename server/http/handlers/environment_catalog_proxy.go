// environment_catalog_proxy.go — server-side endpoints backing RemoteStorage's
// Environment catalog methods (ListEnvironments/ListEnvironmentsByProject/
// ListEnvironmentsByProjectIncludingDeleted/GetEnvironment/DeleteEnvironment/
// RestoreEnvironment).
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies its
// environment-catalog storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/environments* and /api/v1/system/projects/{id}/environments*, gated
// on the existing system.read/system.write RBAC permissions — no new privilege
// class). Exactly the same pattern as project_catalog_proxy.go: thin passthroughs
// onto the SAME storage.Storage primitives
// (internal/storage/store/local_secrets.go's LocalStorage.ListEnvironments et al.)
// internal/core/catalog.go already uses against a local backend — no environment
// POLICY decision (parent-project liveness, the requireAuthorityToReinstateProjectRoles
// admin-ceiling check on restore, audit-log events) is made here; that stays entirely
// in the CALLING server's own internal/core.KeyorixCore, exactly as it does against a
// local backend.
//
// NOTE (#499 carve-out, untouched by #528): CreateSecret's own GetEnvironment call
// site (internal/core/secrets.go) already special-cases errors.Is(ErrUnsupportedByBackend)
// to skip its ownership pre-check when GetEnvironment is unsupported. Now that
// GetEnvironmentProxy makes GetEnvironment actually succeed under storage.type: remote,
// that call site's pre-check simply starts running for real (the upstream server's own
// CreateSecret handler already re-verifies the same invariant authoritatively either
// way) — no code change was needed or made there.
//
// Response envelope: like project_catalog_proxy.go, these do NOT use the package's
// generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// environmentProxyWire mirrors models.Environment's fields exactly (snake_case) —
// the wire shape RemoteStorage's environment methods
// (internal/storage/store/remote_rbac.go) expect. See projectProxyWire's comment for
// why every field is named explicitly (models.Environment carries no json tags).
type environmentProxyWire struct {
	ID        uint       `json:"id"`
	ProjectID uint       `json:"project_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

func newEnvironmentProxyWire(e *models.Environment) environmentProxyWire {
	w := environmentProxyWire{
		ID:        e.ID,
		ProjectID: e.ProjectID,
		Name:      e.Name,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
	if e.DeletedAt.Valid {
		t := e.DeletedAt.Time
		w.DeletedAt = &t
	}
	return w
}

// isEnvironmentNotFound reports whether err is an "environment not found" error from
// LocalStorage (local_secrets.go's GetEnvironment/DeleteEnvironment/RestoreEnvironment
// all use this literal substring).
func isEnvironmentNotFound(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "not found")
}

// ListEnvironmentsProxy handles GET /api/v1/system/environments (global list).
func (h *CatalogHandler) ListEnvironmentsProxy(w http.ResponseWriter, r *http.Request) {
	environments, err := h.coreService.Storage().ListEnvironments(r.Context())
	if err != nil {
		log.Printf("environment catalog proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]environmentProxyWire, 0, len(environments))
	for _, e := range environments {
		wire = append(wire, newEnvironmentProxyWire(e))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"environments": wire})
}

// ListEnvironmentsByProjectProxy handles GET
// /api/v1/system/projects/{id}/environments?include_deleted=true.
func (h *CatalogHandler) ListEnvironmentsByProjectProxy(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid project ID")
		return
	}
	var environments []*models.Environment
	if r.URL.Query().Get("include_deleted") == "true" {
		environments, err = h.coreService.Storage().ListEnvironmentsByProjectIncludingDeleted(r.Context(), uint(projectID))
	} else {
		environments, err = h.coreService.Storage().ListEnvironmentsByProject(r.Context(), uint(projectID))
	}
	if err != nil {
		log.Printf("environment catalog proxy: list by project failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	wire := make([]environmentProxyWire, 0, len(environments))
	for _, e := range environments {
		wire = append(wire, newEnvironmentProxyWire(e))
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"environments": wire})
}

// GetEnvironmentProxy handles GET /api/v1/system/environments/{id}.
func (h *CatalogHandler) GetEnvironmentProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidEnvironmentID)
		return
	}
	env, err := h.coreService.Storage().GetEnvironment(r.Context(), uint(id))
	if err != nil {
		if isEnvironmentNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "environment not found")
			return
		}
		log.Printf("environment catalog proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newEnvironmentProxyWire(env))
}

// DeleteEnvironmentProxy handles DELETE /api/v1/system/environments/{id}.
func (h *CatalogHandler) DeleteEnvironmentProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidEnvironmentID)
		return
	}
	if err := h.coreService.Storage().DeleteEnvironment(r.Context(), uint(id)); err != nil {
		if isEnvironmentNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "environment not found")
			return
		}
		if strings.Contains(err.Error(), "active secret") {
			writeRemoteAPIError(w, http.StatusConflict, "CONFLICT", err.Error())
			return
		}
		log.Printf("environment catalog proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

// RestoreEnvironmentProxy handles POST
// /api/v1/system/projects/{projectId}/environments/{id}/restore.
func (h *CatalogHandler) RestoreEnvironmentProxy(w http.ResponseWriter, r *http.Request) {
	projectID, err := strconv.ParseUint(chi.URLParam(r, "projectId"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid project ID")
		return
	}
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", errInvalidEnvironmentID)
		return
	}
	if err := h.coreService.Storage().RestoreEnvironment(r.Context(), uint(projectID), uint(id)); err != nil {
		if isEnvironmentNotFound(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "environment not found or not deleted")
			return
		}
		log.Printf("environment catalog proxy: restore failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"restored": true})
}
