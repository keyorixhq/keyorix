// sod_proxy.go — server-side endpoints backing RemoteStorage's
// separation-of-duties (SoD) policy storage primitives (finding #519):
// CreateSoDPolicy/GetSoDPolicy/ListSoDPolicies/DeleteSoDPolicy.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// its SoD-policy storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/sod-policies, gated on the existing system.read/system.write
// RBAC permissions — the SAME credential a RemoteStorage client already needs for
// every other proxied call, e.g. full user CRUD, project-membership CRUD (#511),
// so this introduces no new privilege class). Mirrors project_memberships_proxy.go
// (#511) and dynamic_secrets_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/sod.go already uses against a local backend — NO SoD-policy
// POLICY decision (name/permission-pair validation — required, distinct — the
// audit-log event, or the violation-detection scan itself, DetectSoDViolations)
// is made here; all of that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// This is deliberately NOT a reuse of CatalogHandler's existing human-facing
// /api/v1/sod/policies routes (server/http/handlers/sod.go), exactly like the
// human-facing /groups routes were the wrong proxy target for the group-CRUD
// proxy (round-116 finding, groups_proxy.go): CreateSoDPolicy/DeleteSoDPolicy
// there require an authenticated actor from the HTTP request context and run
// THIS server's own core.CreateSoDPolicy/DeleteSoDPolicy (validation +
// audit-event write) — the wrong semantics for a raw storage-primitive
// passthrough, whose caller already ran all of that on the downstream side and
// only needs this server to persist/return the already-validated row.
//
// models.SoDPolicy already carries full explicit json tags (unlike
// models.DynamicSecretConfig/models.ProjectMembership before their own proxy
// fixes), so no separate wire-DTO struct is needed here — the model is
// marshaled/unmarshaled directly, same as remote_rotation_policies.go's
// pre-existing (non-system-proxy) precedent.
//
// Response envelope: like the other proxies in this package, these do NOT use
// the package's generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
// internal/storage/remote.HTTPClient parses (its APIResponse/APIError types).
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// CreateSoDPolicyProxy handles POST /api/v1/system/sod-policies. Persists the
// caller's already-fully-validated policy row as-is (a raw storage-layer
// create) — matching CreateMembershipProxy's precedent, this is NOT the
// human-facing POST /api/v1/sod/policies (CatalogHandler.CreateSoDPolicy),
// which additionally requires an authenticated actor and runs this server's own
// name/permission-pair validation and audit-event write.
func (h *CatalogHandler) CreateSoDPolicyProxy(w http.ResponseWriter, r *http.Request) {
	var body models.SoDPolicy
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "invalid request body")
		return
	}
	if body.Name == "" || body.PermissionA == "" || body.PermissionB == "" {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "name, permission_a, and permission_b are required")
		return
	}
	created, err := h.coreService.Storage().CreateSoDPolicy(r.Context(), &body)
	if err != nil {
		log.Printf("sod-policies proxy: create failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, created)
}

// GetSoDPolicyProxy handles GET /api/v1/system/sod-policies/{id}.
func (h *CatalogHandler) GetSoDPolicyProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid policy id")
		return
	}
	policy, err := h.coreService.Storage().GetSoDPolicy(r.Context(), uint(id))
	if err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "SoD policy not found")
			return
		}
		log.Printf("sod-policies proxy: get failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, policy)
}

// ListSoDPoliciesProxy handles GET /api/v1/system/sod-policies.
func (h *CatalogHandler) ListSoDPoliciesProxy(w http.ResponseWriter, r *http.Request) {
	rows, err := h.coreService.Storage().ListSoDPolicies(r.Context())
	if err != nil {
		log.Printf("sod-policies proxy: list failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]interface{}{"policies": rows})
}

// DeleteSoDPolicyProxy handles DELETE /api/v1/system/sod-policies/{id}.
func (h *CatalogHandler) DeleteSoDPolicyProxy(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid policy id")
		return
	}
	if err := h.coreService.Storage().DeleteSoDPolicy(r.Context(), uint(id)); err != nil {
		if isNotFoundErr(err) {
			writeRemoteAPIError(w, http.StatusNotFound, "NOT_FOUND", "SoD policy not found")
			return
		}
		log.Printf("sod-policies proxy: delete failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
}
