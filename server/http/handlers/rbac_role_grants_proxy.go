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
// Most of these were originally thin passthroughs straight onto storage.Storage,
// on the theory that no RBAC POLICY decision needs to be made here because the
// CALLING server's own internal/core.KeyorixCore already made it before
// deciding to relay the write. #1542: that theory only holds for a genuine
// node-credential relay — this route group's gate
// (RequireNodeCredentialOrPermission) also admits any caller (human or
// machine) holding the system.write PERMISSION directly, with no node
// credential at all, and THAT caller is not relaying anyone's already-checked
// decision. A raw storage passthrough gave such a caller a clean path to
// global admin with zero ceiling checks of any kind. AssignRoleWithExpiryProxy/
// AssignRoleToGroupWithExpiryProxy/AssignMachineRoleProxy/
// RemoveAllProjectRoleGrantsProxy now route through the SAME internal/core
// functions (AssignUserRoleWithExpiry, AssignGroupRoleWithExpiry,
// AssignMachineRole, RemoveProjectMember) a local backend would use, so their
// real ceiling checks run for a direct system.write caller. A genuine node
// relay is still trusted for the one check (requireGranterHoldsRolePermissions)
// that can't distinguish "the real acting human already passed this" from "the
// node itself holds no permissions" without a wire-level actor-identity field
// that doesn't exist yet (isNodeCredentialRequest, catalog.go) — see each
// handler's own doc for why the others need no such carve-out.
//
// This is deliberately NOT a reuse of RBACHandler/GroupHandler's existing
// human-facing routes (POST /groups/{id}/members, DELETE
// /projects/{id}/members/{userId}, etc.): those require an authenticated actor
// from the HTTP request context and run THIS server's own core methods
// (validation, audit-log writes, last-admin/last-project-admin ceiling checks)
// against THIS server's identity — the wrong semantics for a raw storage-primitive
// passthrough, whose caller already ran all of that on the downstream side and
// only needs this server to persist/return the already-decided row (still true
// for the routes in this group that remain plain passthroughs). Exactly the
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
	"context"
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
//
// #1542: previously called storage.AssignRoleWithExpiry directly, bypassing
// every core ceiling (requireGranterHoldsRolePermissions, #419 SoD) for ANY
// system.write holder, human or machine — reaching global admin. A genuine
// node-credential relay is trusted to have already run that ceiling locally
// against the real acting human (see the package doc); a caller reaching
// this route via the system.write PERMISSION arm without a node credential
// is not relaying anyone's decision, so it's routed through
// core.AssignUserRoleWithExpiry, running the real ceiling against ITS OWN
// authority instead.
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
	var err error
	if isNodeCredentialRequest(r) {
		err = h.coreService.Storage().AssignRoleWithExpiry(r.Context(), body.UserID, body.RoleID, scope, body.ExpiresAt)
	} else {
		err = h.coreService.AssignUserRoleWithExpiry(r.Context(), actorID(r), body.UserID, body.RoleID, scope, body.ExpiresAt, isMachineActor(r))
	}
	if err != nil {
		log.Printf("rbac role-grants proxy: assign role with expiry failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"assigned": true})
}

// AssignRoleToGroupWithExpiryProxy handles POST
// /api/v1/system/rbac/assign-role-to-group-with-expiry.
//
// #1542: routed through core.AssignGroupRoleWithExpiry instead of calling
// storage.AssignRoleToGroupWithExpiry directly. Unlike AssignRoleWithExpiryProxy,
// no node-vs-direct-caller branch is needed here: AssignGroupRoleWithExpiry's
// ceiling (requireAuthorityForRole) only evaluates anything for admin-tier
// roles, and for those it already denies actorID==0 with no special-casing
// (the same construction PlaceLegalHold/LiftLegalHold/RestoreProject's
// admin-tier branch rely on — see docs/adr-085-node-credential-permission-scope.md) —
// correct for a node relay AND a direct system.write caller alike. A
// non-admin-tier grant (the ordinary relay case) passes through unchanged.
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
	if err := h.coreService.AssignGroupRoleWithExpiry(r.Context(), actorID(r), body.GroupID, body.RoleID, scope, body.ExpiresAt); err != nil {
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
//
// #1542: routed through core.RemoveProjectMember instead of calling
// storage.RemoveAllProjectRoleGrants directly, so guardLastProjectAdmin (the
// last-project-admin availability check) actually runs. No node-vs-direct
// branch needed: guardLastProjectAdmin is target-state-invariant — it only
// asks whether removing this grant leaves the project with zero
// roles.assign holders, never who's asking — safe for any caller including
// a bare node credential, by construction.
//
// core.ErrNotProjectMember is treated as success: the raw storage delete this
// replaced was an unconditional, idempotent DELETE ... WHERE (no error on
// zero rows matched); RemoveProjectMember returns ErrNotProjectMember for the
// same "nothing to remove" case, and a relay caller that legitimately retries
// or calls this defensively must see the same idempotent result as before,
// not a new error for a case that was never actually a failure. Matches the
// established convention at membership_lifecycle.go:316.
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
	if err := h.coreService.RemoveProjectMember(r.Context(), actorID(r), body.ProjectID, body.UserID); err != nil && !errors.Is(err, core.ErrNotProjectMember) {
		log.Printf("rbac role-grants proxy: remove all project role grants failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"removed": true})
}

// clearProjectSecretOwnershipWire is the request body for
// ClearProjectSecretOwnershipProxy.
type clearProjectSecretOwnershipWire struct {
	UserID    uint `json:"user_id"`
	ProjectID uint `json:"project_id"`
}

// ClearProjectSecretOwnershipProxy handles POST
// /api/v1/system/rbac/clear-project-secret-ownership (RBAC-002).
func (h *RBACHandler) ClearProjectSecretOwnershipProxy(w http.ResponseWriter, r *http.Request) {
	var body clearProjectSecretOwnershipWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.ProjectID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and project_id are required")
		return
	}
	if err := h.coreService.Storage().ClearProjectSecretOwnership(r.Context(), body.UserID, body.ProjectID); err != nil {
		log.Printf("rbac proxy: clear project secret ownership failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"cleared": true})
}

// deleteSecretACLsByUserAndProjectWire is the request body for
// DeleteSecretACLsByUserAndProjectProxy.
type deleteSecretACLsByUserAndProjectWire struct {
	UserID    uint `json:"user_id"`
	ProjectID uint `json:"project_id"`
}

// DeleteSecretACLsByUserAndProjectProxy handles POST
// /api/v1/system/rbac/delete-secret-acls-by-user-and-project (#G13/CWE-284).
func (h *RBACHandler) DeleteSecretACLsByUserAndProjectProxy(w http.ResponseWriter, r *http.Request) {
	var body deleteSecretACLsByUserAndProjectWire
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", errInvalidBody)
		return
	}
	if body.UserID == 0 || body.ProjectID == 0 {
		writeRemoteAPIError(w, http.StatusBadRequest, "INVALID_BODY", "user_id and project_id are required")
		return
	}
	if err := h.coreService.Storage().DeleteSecretACLsByUserAndProject(r.Context(), body.UserID, body.ProjectID); err != nil {
		log.Printf("rbac proxy: delete secret ACLs by user and project failed: %v", err)
		writeRemoteAPIError(w, http.StatusInternalServerError, "STORAGE_ERROR", clientSafe(err))
		return
	}
	writeRemoteAPISuccess(w, map[string]bool{"deleted": true})
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
// RemoveGlobalAdminRoleGuardedProxy. AdminRoleIDs is accepted for wire
// compatibility with older RemoteStorage clients but is IGNORED — see
// resolveInstallAdminRoleIDsProxy's doc for why (#G79).
type removeGlobalAdminRoleGuardedProxyWire struct {
	UserID       uint   `json:"user_id"`
	RoleID       uint   `json:"role_id"`
	AdminRoleIDs []uint `json:"admin_role_ids"`
}

// resolveInstallAdminRoleIDsProxy resolves installAdminRoleNames
// (internal/core/rbac_management.go's unexported admin-role-name list,
// duplicated here — identical to breakGlassContainmentAdminRoleNames in
// break_glass_proxy.go) to role IDs against THIS server's own role table.
//
// #G79: RemoveGlobalAdminRoleGuardedProxy previously took the admin-role-ID
// set straight from the wire body (removeGlobalAdminRoleGuardedProxyWire.
// AdminRoleIDs) and passed it directly to storage.RemoveGlobalAdminRoleGuarded,
// which uses that set to count how many OTHER admin-conferring grants the
// target user holds before allowing the removal. core.RemoveUserRole's local
// equivalent (RemoveUserRole, rbac_management.go) never trusts a
// caller-supplied set for this — it always resolves installAdminRoleIDSet
// itself. A caller reachable directly via system.write (bypassing the calling
// server's own RemoveUserRole) could otherwise submit an incomplete or empty
// admin_role_ids list, making the last-admin count undercount and letting the
// guard silently strand (or fail to detect stranding) the install's last
// global admin. Resolve the set server-side instead of trusting the wire.
func resolveInstallAdminRoleIDsProxy(ctx context.Context, st coreStorage.Storage) []uint {
	ids := make([]uint, 0, len(breakGlassContainmentAdminRoleNames))
	for _, name := range breakGlassContainmentAdminRoleNames {
		if role, err := st.GetRoleByName(ctx, name); err == nil && role != nil {
			ids = append(ids, role.ID)
		}
	}
	return ids
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
	adminRoleIDs := resolveInstallAdminRoleIDsProxy(r.Context(), h.coreService.Storage())
	err := h.coreService.Storage().RemoveGlobalAdminRoleGuarded(r.Context(), body.UserID, body.RoleID, adminRoleIDs)
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
