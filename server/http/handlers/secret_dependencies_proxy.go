// secret_dependencies_proxy.go — server-side endpoints backing RemoteStorage's secret
// dependency-graph storage primitives (ADR-052): CreateSecretDependency/
// GetSecretDependency/ListSecretDependenciesForProject/
// ListSecretDependenciesForProjectForUpdate/DeleteSecretDependency/
// CreateSecretDependencyExclusive.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies its
// secret-dependency storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/secret-dependencies, gated on the existing system.read/system.write
// RBAC permissions — the SAME credential a RemoteStorage client already needs for
// every other proxied call, so this introduces no new privilege class). Mirrors
// dynamic_secrets_proxy.go/project_memberships_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/secret_dependencies.go already uses against a local backend — NO
// dependency-graph POLICY decision (which secrets a caller may link, environment/
// project scoping, audit logging) is made here; all of that stays entirely in the
// CALLING server's own internal/core.KeyorixCore, exactly as it does against a local
// backend.
//
// This also means the SecretHandler's existing human-facing
// /api/v1/secrets/{id}/dependencies routes (secret_dependencies.go) are NOT reused for
// this proxy: AddSecretDependency there runs THIS server's own core.AddSecretDependency
// (including its own same-project/same-environment/self-edge/duplicate/cycle checks
// against the HTTP caller's identity) — the wrong semantics for a raw storage-primitive
// passthrough, whose caller already ran its OWN core logic and only needs this server
// to persist/return rows, exactly like the human-facing /groups routes were the wrong
// proxy target for Group storage (a prior fix in this same campaign).
//
// One deliberate exception: CreateSecretDependencyExclusiveProxy calls
// storage.CreateSecretDependencyExclusive, which DOES evaluate the duplicate/cycle
// invariant — not because that's this server's OWN policy decision, but because no
// real transaction can span the HTTP hop back to the calling server (RemoteStorage.
// WithTransaction is a no-op passthrough), so whichever server ultimately owns the
// row is the only one that CAN enforce it atomically. See the storage.Storage
// interface doc (internal/core/storage/interface.go) for the full reasoning.
//
// Response envelope: like the other proxies, these do NOT use the package's generic
// sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// secretDependencyProxyWire mirrors models.SecretDependency's fields exactly
// (snake_case) — see remote_secret_dependencies.go's identically-shaped wire type for
// why (a GORM model with no json tags of its own).
type secretDependencyProxyWire struct {
	ID                uint      `json:"id"`
	ProjectID         uint      `json:"project_id"`
	DependentSecretID uint      `json:"dependent_secret_id"`
	DependsOnSecretID uint      `json:"depends_on_secret_id"`
	Note              string    `json:"note,omitempty"`
	CreatedBy         uint      `json:"created_by,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
}

func newSecretDependencyProxyWire(d *models.SecretDependency) secretDependencyProxyWire {
	return secretDependencyProxyWire{
		ID:                d.ID,
		ProjectID:         d.ProjectID,
		DependentSecretID: d.DependentSecretID,
		DependsOnSecretID: d.DependsOnSecretID,
		Note:              d.Note,
		CreatedBy:         d.CreatedBy,
		CreatedAt:         d.CreatedAt,
	}
}

func (w secretDependencyProxyWire) toModel() *models.SecretDependency {
	return &models.SecretDependency{
		ID:                w.ID,
		ProjectID:         w.ProjectID,
		DependentSecretID: w.DependentSecretID,
		DependsOnSecretID: w.DependsOnSecretID,
		Note:              w.Note,
		CreatedBy:         w.CreatedBy,
		CreatedAt:         w.CreatedAt,
	}
}

// duplicateSecretDependencyCode/secretDependencyCycleCode are the machine-readable
// error codes this proxy returns when CreateSecretDependencyExclusive rejects an edge —
// mirrored EXACTLY (same string values) in
// internal/storage/store/remote_secret_dependencies.go, the wire-level contract
// RemoteStorage.CreateSecretDependencyExclusive's error-recovery switch depends on to
// reconstruct storage.ErrDuplicateSecretDependency/storage.ErrSecretDependencyCycle on
// the calling side (#511-style wire-code translation).
const (
	duplicateSecretDependencyCode = "DUPLICATE_SECRET_DEPENDENCY"
	secretDependencyCycleCode     = "SECRET_DEPENDENCY_CYCLE"
)

// crossReferenceSecretDependencyProxy verifies that dependentID/dependsOnID
// are both real secrets that actually belong to projectID and share the same
// environment — the same same-project/same-environment check
// core.AddSecretDependency applies (secret_dependencies.go) before it will
// accept an edge. #G79: without this, CreateSecretDependencyProxy/
// CreateSecretDependencyExclusiveProxy accepted any ProjectID/
// DependentSecretID/DependsOnSecretID combination the caller supplied, with
// no cross-reference to what those IDs actually resolve to — letting a
// caller record a dependency edge that names secrets in an entirely
// different project/environment than the one it claims.
func crossReferenceSecretDependencyProxy(ctx context.Context, h *SecretHandler, projectID, dependentID, dependsOnID uint) error {
	dependent, err := h.coreService.Storage().GetSecret(ctx, dependentID)
	if err != nil || dependent.ProjectID != projectID {
		return fmt.Errorf("dependent_secret_id does not belong to project_id")
	}
	dependsOn, err := h.coreService.Storage().GetSecret(ctx, dependsOnID)
	if err != nil || dependsOn.ProjectID != projectID || dependsOn.EnvironmentID != dependent.EnvironmentID {
		return fmt.Errorf("depends_on_secret_id must be a secret in the same project and environment")
	}
	return nil
}

// CreateSecretDependencyProxy handles POST /api/v1/system/secret-dependencies. A raw,
// unconditional persist (storage.Storage.CreateSecretDependency), kept for interface
// parity — AddSecretDependency's real add path goes through
// CreateSecretDependencyExclusiveProxy below instead.
func (h *SecretHandler) CreateSecretDependencyProxy(w http.ResponseWriter, r *http.Request) {
	var body secretDependencyProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.ProjectID == 0 || body.DependentSecretID == 0 || body.DependsOnSecretID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id, dependent_secret_id, and depends_on_secret_id are required")
		return
	}
	if err := crossReferenceSecretDependencyProxy(r.Context(), h, body.ProjectID, body.DependentSecretID, body.DependsOnSecretID); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	created, err := h.coreService.Storage().CreateSecretDependency(r.Context(), body.toModel())
	if err != nil {
		log.Printf("secret-dependencies proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSecretDependencyProxyWire(created))
}

// CreateSecretDependencyExclusiveProxy handles POST
// /api/v1/system/secret-dependencies/exclusive. See the package doc and the
// storage.Storage interface doc for why this atomically validates the edge (duplicate/
// cycle rejection) rather than being a raw passthrough like every other method here.
func (h *SecretHandler) CreateSecretDependencyExclusiveProxy(w http.ResponseWriter, r *http.Request) {
	var body secretDependencyProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.ProjectID == 0 || body.DependentSecretID == 0 || body.DependsOnSecretID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "project_id, dependent_secret_id, and depends_on_secret_id are required")
		return
	}
	if err := crossReferenceSecretDependencyProxy(r.Context(), h, body.ProjectID, body.DependentSecretID, body.DependsOnSecretID); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", err.Error())
		return
	}
	// #G79: routed through core.LockedCreateSecretDependencyExclusive (holds the
	// same secretDependencyMu core.AddSecretDependency holds around the identical
	// storage call) rather than calling storage.CreateSecretDependencyExclusive
	// directly — see that method's doc for why the storage-layer cycle check alone
	// isn't race-safe against two concurrent same-process proxy requests.
	created, err := h.coreService.LockedCreateSecretDependencyExclusive(r.Context(), body.toModel())
	if err != nil {
		switch {
		case errors.Is(err, coreStorage.ErrDuplicateSecretDependency):
			writeRemoteAPIError(w, http.StatusConflict, duplicateSecretDependencyCode, coreStorage.ErrDuplicateSecretDependency.Error())
		case errors.Is(err, coreStorage.ErrSecretDependencyCycle):
			writeRemoteAPIError(w, http.StatusBadRequest, secretDependencyCycleCode, coreStorage.ErrSecretDependencyCycle.Error())
		default:
			log.Printf("secret-dependencies proxy: exclusive create failed: %v", err)
			writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		}
		return
	}
	writeRemoteAPISuccess(w, newSecretDependencyProxyWire(created))
}

// GetSecretDependencyProxy handles GET /api/v1/system/secret-dependencies/{id}.
func (h *SecretHandler) GetSecretDependencyProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid dependency id")
		return
	}
	d, err := h.coreService.Storage().GetSecretDependency(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "secret dependency not found")
			return
		}
		log.Printf("secret-dependencies proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, newSecretDependencyProxyWire(d))
}

// ListSecretDependenciesForProjectProxy handles GET
// /api/v1/system/secret-dependencies?project_id=X.
func (h *SecretHandler) ListSecretDependenciesForProjectProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProxyProjectIDQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListSecretDependenciesForProject(r.Context(), projectID)
	if err != nil {
		log.Printf("secret-dependencies proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"dependencies": newSecretDependencyProxyWireList(rows)})
}

// ListSecretDependenciesForProjectForUpdateProxy handles GET
// /api/v1/system/secret-dependencies/for-update?project_id=X (a static path, registered
// before /secret-dependencies/{id} in router.go). Kept for interface parity — see this
// method's doc on RemoteStorage (remote_secret_dependencies.go) for why it takes no
// lock over this hop.
func (h *SecretHandler) ListSecretDependenciesForProjectForUpdateProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProxyProjectIDQuery(w, r)
	if !ok {
		return
	}
	rows, err := h.coreService.Storage().ListSecretDependenciesForProjectForUpdate(r.Context(), projectID)
	if err != nil {
		log.Printf("secret-dependencies proxy: list-for-update failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"dependencies": newSecretDependencyProxyWireList(rows)})
}

// DeleteSecretDependencyProxy handles DELETE /api/v1/system/secret-dependencies/{id}.
func (h *SecretHandler) DeleteSecretDependencyProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid dependency id")
		return
	}
	if err := h.coreService.Storage().DeleteSecretDependency(r.Context(), uint(id)); err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "secret dependency not found")
			return
		}
		log.Printf("secret-dependencies proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}

func newSecretDependencyProxyWireList(rows []*models.SecretDependency) []secretDependencyProxyWire {
	wire := make([]secretDependencyProxyWire, 0, len(rows))
	for _, d := range rows {
		wire = append(wire, newSecretDependencyProxyWire(d))
	}
	return wire
}

// parseProxyProjectIDQuery parses the required project_id query parameter shared by
// ListSecretDependenciesForProjectProxy/ListSecretDependenciesForProjectForUpdateProxy.
func parseProxyProjectIDQuery(w http.ResponseWriter, r *http.Request) (projectID uint, ok bool) {
	v := r.URL.Query().Get("project_id")
	if v == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id query parameter is required")
		return 0, false
	}
	id, err := strconv.ParseUint(v, 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "project_id must be a valid integer")
		return 0, false
	}
	return uint(id), true
}
