// rbac_role_grants_proxy.go — server-side endpoints backing RemoteStorage's
// RBAC role-grant primitives (finding #525): GetGroupRoleGrants/
// AssignRoleWithExpiry/AssignRoleToGroupWithExpiry/RemoveAllProjectRoleGrants/
// ListGroupRoleAssignments/ListGlobalAdminAssignmentsForUpdate/
// ListProjectRoleAssignments/ListProjectMachineRoleAssignments/
// RemoveGlobalAdminRoleGuarded.
//
// A downstream Keyorix server booted with storage.type: remote (ADR-049) proxies
// these RBAC role-grant storage calls to whichever upstream server it's configured
// against, through these routes (registered in server/http/router.go under
// /api/v1/system/rbac, gated on the existing system.read/system.write RBAC
// permissions — the SAME credential a RemoteStorage client already needs for every
// other proxied call, so this introduces no new privilege class). Mirrors
// secret_dependencies_proxy.go/retention_proxy.go exactly.
//
// These are thin passthroughs onto the SAME storage.Storage primitives
// internal/core/jit_access.go, project_members.go, groups.go, and
// rbac_management.go already use against a local backend — no RBAC POLICY
// decision (escalation-by-proxy ceiling checks, separation-of-duties, audit-log
// writes) is made here; that stays entirely in the CALLING server's own
// internal/core.KeyorixCore, exactly as it does against a local backend.
//
// This is deliberately NOT a reuse of RBACHandler/GroupHandler's existing
// human-facing routes (POST /groups/{id}/members, DELETE
// /projects/{id}/members/{userId}, etc.): those require an authenticated actor
// from the HTTP request context and run THIS server's own core methods
// (validation, audit-log writes, last-admin/last-project-admin ceiling checks)
// against THIS server's identity — the wrong semantics for a raw storage-primitive
// passthrough, whose caller already ran all of that on the downstream side and
// only needs this server to persist/return the already-decided row. Exactly the
// same reasoning the #519/#520/#527 proxies in this package already established.
//
// One deliberate exception: RemoveGlobalAdminRoleGuardedProxy calls
// storage.RemoveGlobalAdminRoleGuarded, which DOES evaluate the last-global-admin
// invariant server-side — not because that's this server's OWN policy decision,
// but because no real transaction can span the HTTP hop back to the calling
// server (RemoteStorage.WithTransaction is a no-op passthrough), so whichever
// server ultimately owns the row is the only one that CAN enforce it atomically.
// See the storage.Storage interface doc (internal/core/storage/interface.go) and
// internal/core/rbac_management.go's RemoveUserRole doc for the full reasoning —
// the same pattern CreateSecretDependencyExclusiveProxy (#260) and
// AdvanceWebAuthnCredentialCounterProxy (#306/#517) already established for their
// own TOCTOU classes.
//
// Response envelope: like the other proxies, these do NOT use the package's
// generic sendSuccess/sendError helpers — they construct the exact
// {"success":bool,"data":...,"error":{"code","message"}} shape
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
)


// roleWithExpiryProxyWire mirrors internal/storage/store/remote_rbac.go's
// roleWithExpiryWire exactly — the shared wire body for
// AssignRoleWithExpiryProxy (UserID set, GroupID zero) and
// AssignRoleToGroupWithExpiryProxy (GroupID set, UserID zero).
type roleWithExpiryProxyWire struct {
	UserID        uint      `json:"user_id,omitempty"`
	GroupID       uint      `json:"group_id,omitempty"`
	RoleID        uint      `json:"role_id"`
	ProjectID     uint      `json:"project_id"`
	EnvironmentID uint      `json:"environment_id"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// GetGroupRoleGrantsProxy handles GET
// /api/v1/system/rbac/groups/{groupID}/role-grants.
func (h *RBACHandler) GetGroupRoleGrantsProxy(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseUint(chi.URLParam(r, "groupID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid group id")
		return
	}
	grants, err := h.coreService.Storage().GetGroupRoleGrants(r.Context(), uint(groupID))
	if err != nil {
		log.Printf("rbac role-grants proxy: get group role grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, grants)
}

// AssignRoleWithExpiryProxy handles POST
// /api/v1/system/rbac/assign-role-with-expiry.
func (h *RBACHandler) AssignRoleWithExpiryProxy(w http.ResponseWriter, r *http.Request) {
	var body roleWithExpiryProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.RoleID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and role_id are required")
		return
	}
	scope := coreStorage.Scope{ProjectID: body.ProjectID, EnvironmentID: body.EnvironmentID}
	if err := h.coreService.Storage().AssignRoleWithExpiry(r.Context(), body.UserID, body.RoleID, scope, body.ExpiresAt); err != nil {
		log.Printf("rbac role-grants proxy: assign role with expiry failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"assigned": true})
}

// AssignRoleToGroupWithExpiryProxy handles POST
// /api/v1/system/rbac/assign-role-to-group-with-expiry.
func (h *RBACHandler) AssignRoleToGroupWithExpiryProxy(w http.ResponseWriter, r *http.Request) {
	var body roleWithExpiryProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.GroupID == 0 || body.RoleID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "group_id and role_id are required")
		return
	}
	scope := coreStorage.Scope{ProjectID: body.ProjectID, EnvironmentID: body.EnvironmentID}
	if err := h.coreService.Storage().AssignRoleToGroupWithExpiry(r.Context(), body.GroupID, body.RoleID, scope, body.ExpiresAt); err != nil {
		log.Printf("rbac role-grants proxy: assign role to group with expiry failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"assigned": true})
}

// removeAllProjectRoleGrantsProxyWire is the request body for
// RemoveAllProjectRoleGrantsProxy.
type removeAllProjectRoleGrantsProxyWire struct {
	UserID    uint `json:"user_id"`
	ProjectID uint `json:"project_id"`
}

// RemoveAllProjectRoleGrantsProxy handles POST
// /api/v1/system/rbac/remove-all-project-role-grants.
func (h *RBACHandler) RemoveAllProjectRoleGrantsProxy(w http.ResponseWriter, r *http.Request) {
	var body removeAllProjectRoleGrantsProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.ProjectID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and project_id are required")
		return
	}
	if err := h.coreService.Storage().RemoveAllProjectRoleGrants(r.Context(), body.UserID, body.ProjectID); err != nil {
		log.Printf("rbac role-grants proxy: remove all project role grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"removed": true})
}

// ListGroupRoleAssignmentsProxy handles GET
// /api/v1/system/rbac/groups/{groupID}/role-assignments.
func (h *RBACHandler) ListGroupRoleAssignmentsProxy(w http.ResponseWriter, r *http.Request) {
	groupID, err := strconv.ParseUint(chi.URLParam(r, "groupID"), 10, 32)
	if err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_PARAMETER", "invalid group id")
		return
	}
	assignments, err := h.coreService.Storage().ListGroupRoleAssignments(r.Context(), uint(groupID))
	if err != nil {
		log.Printf("rbac role-grants proxy: list group role assignments failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, assignments)
}

// ListProjectRoleAssignmentsProxy handles GET
// /api/v1/system/rbac/project-role-assignments?project_id=X.
func (h *RBACHandler) ListProjectRoleAssignmentsProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseRBACProxyProjectIDQuery(w, r)
	if !ok {
		return
	}
	assignments, err := h.coreService.Storage().ListProjectRoleAssignments(r.Context(), projectID)
	if err != nil {
		log.Printf("rbac role-grants proxy: list project role assignments failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, assignments)
}

// ListProjectMachineRoleAssignmentsProxy handles GET
// /api/v1/system/rbac/project-machine-role-assignments?project_id=X.
func (h *RBACHandler) ListProjectMachineRoleAssignmentsProxy(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseRBACProxyProjectIDQuery(w, r)
	if !ok {
		return
	}
	assignments, err := h.coreService.Storage().ListProjectMachineRoleAssignments(r.Context(), projectID)
	if err != nil {
		log.Printf("rbac role-grants proxy: list project machine role assignments failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, assignments)
}

// ListGlobalAdminAssignmentsForUpdateProxy handles GET
// /api/v1/system/rbac/global-admin-assignments?role_ids=1,2,3. A PLAIN read — see
// RemoteStorage.ListGlobalAdminAssignmentsForUpdate's doc (remote_rbac.go) for why
// no lock is taken over this hop; safety comes entirely from
// RemoveGlobalAdminRoleGuardedProxy's atomic conditional write below.
func (h *RBACHandler) ListGlobalAdminAssignmentsForUpdateProxy(w http.ResponseWriter, r *http.Request) {
	roleIDs, ok := parseRBACProxyRoleIDsQuery(w, r)
	if !ok {
		return
	}
	assignments, err := h.coreService.Storage().ListGlobalAdminAssignmentsForUpdate(r.Context(), roleIDs)
	if err != nil {
		log.Printf("rbac role-grants proxy: list global admin assignments failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, assignments)
}

// removeGlobalAdminRoleGuardedProxyWire is the request body for
// RemoveGlobalAdminRoleGuardedProxy.
type removeGlobalAdminRoleGuardedProxyWire struct {
	UserID       uint   `json:"user_id"`
	RoleID       uint   `json:"role_id"`
	AdminRoleIDs []uint `json:"admin_role_ids"`
}

// removeGlobalAdminRoleGuardedRefusedCode/notAssignedCode are the machine-readable
// error codes this proxy returns when RemoveGlobalAdminRoleGuarded rejects the
// removal — mirrored EXACTLY (same string values) in
// internal/storage/store/remote_rbac.go, the wire-level contract
// RemoteStorage.RemoveGlobalAdminRoleGuarded's error-recovery switch depends on to
// reconstruct storage.ErrWouldStrandLastAdmin/storage.ErrRoleNotAssigned on the
// calling side (#511-style wire-code translation, the same one
// CreateSecretDependencyExclusiveProxy's duplicate/cycle codes use).
const (
	removeGlobalAdminRoleGuardedRefusedCode = "WOULD_STRAND_LAST_ADMIN"
	roleNotAssignedCode                     = "ROLE_NOT_ASSIGNED"
)

// RemoveGlobalAdminRoleGuardedProxy handles POST
// /api/v1/system/rbac/global-admin-role/remove-guarded. See the package doc and
// the storage.Storage interface doc for why this atomically validates the
// last-global-admin invariant rather than being a raw passthrough like every
// other method here.
func (h *RBACHandler) RemoveGlobalAdminRoleGuardedProxy(w http.ResponseWriter, r *http.Request) {
	var body removeGlobalAdminRoleGuardedProxyWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.RoleID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and role_id are required")
		return
	}
	err := h.coreService.Storage().RemoveGlobalAdminRoleGuarded(r.Context(), body.UserID, body.RoleID, body.AdminRoleIDs)
	if err != nil {
		switch {
		case errors.Is(err, coreStorage.ErrWouldStrandLastAdmin):
			writeRemoteAPIError(w, http.StatusConflict, removeGlobalAdminRoleGuardedRefusedCode, coreStorage.ErrWouldStrandLastAdmin.Error())
		case errors.Is(err, coreStorage.ErrRoleNotAssigned):
			writeRemoteAPIError(w, http.StatusNotFound, roleNotAssignedCode, coreStorage.ErrRoleNotAssigned.Error())
		default:
			log.Printf("rbac role-grants proxy: remove global admin role guarded failed: %v", err)
			writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		}
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"removed": true})
}

// parseRBACProxyProjectIDQuery parses the required project_id query parameter
// shared by ListProjectRoleAssignmentsProxy/ListProjectMachineRoleAssignmentsProxy.
func parseRBACProxyProjectIDQuery(w http.ResponseWriter, r *http.Request) (projectID uint, ok bool) {
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

// parseRBACProxyRoleIDsQuery parses the optional, comma-separated role_ids query
// parameter ListGlobalAdminAssignmentsForUpdateProxy takes — an empty/absent value
// is valid (no install-admin role seeded yet) and yields an empty slice, mirroring
// LocalStorage.ListGlobalAdminAssignmentsForUpdate's own "len(adminRoleIDs) == 0 →
// nil, nil" short-circuit.
func parseRBACProxyRoleIDsQuery(w http.ResponseWriter, r *http.Request) (roleIDs []uint, ok bool) {
	v := r.URL.Query().Get("role_ids")
	if v == "" {
		return nil, true
	}
	parts := strings.Split(v, ",")
	ids := make([]uint, 0, len(parts))
	for _, p := range parts {
		id, err := strconv.ParseUint(strings.TrimSpace(p), 10, 32)
		if err != nil {
			writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_QUERY", "role_ids must be a comma-separated list of integers")
			return nil, false
		}
		ids = append(ids, uint(id))
	}
	return ids, true
}
