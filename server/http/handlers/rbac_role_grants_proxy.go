// rbac_role_grants_proxy.go — server-side endpoints backing RemoteStorage's
// RBAC role-grant primitives (finding #525): GetGroupRoleGrants/
// AssignRoleWithExpiry/AssignRoleToGroupWithExpiry/RemoveAllProjectRoleGrants/
// ListGroupRoleAssignments/ListProjectRoleAssignments/
// ListProjectMachineRoleAssignments/RemoveGlobalAdminRoleGuarded.
//
// ListGlobalAdminAssignmentsSnapshotProxy (backed
// ListGlobalAdminAssignmentsForUpdate) was removed (#1480) — dead since #525
// replaced its only real caller, RemoveUserRole's separate pre-read, with
// RemoveGlobalAdminRoleGuarded's single atomic conditional write; no
// internal/core caller remained, and its only real HTTP caller, repo-wide,
// was itself.
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
// deciding to relay the write. #1542: that theory never held for a direct
// system.write caller (human or machine) — this route group's gate admits any
// such caller, and a raw storage passthrough gave them a clean path to global
// admin with zero ceiling checks of any kind. It also, for a while, carved out
// an exemption for a genuine node-credential relay (isNodeCredentialRequest),
// on the theory that a node relays an already-authorized downstream decision.
// ADR-085 (Accepted, 2026-08-25) found that theory false too — the "downstream
// Keyorix node" topology it depended on cannot exist in this codebase
// (ADR-083's validateRemoteStorageNotServer rejects storage.type: remote for
// any server process) — and removed the node-credential exemption entirely.
// AssignRoleWithExpiryProxy/AssignRoleToGroupWithExpiryProxy/
// AssignMachineRoleProxy/RemoveAllProjectRoleGrantsProxy/
// RemoveGlobalAdminRoleGuardedProxy now ALL route through the SAME
// internal/core functions (AssignUserRoleWithExpiry, AssignGroupRoleWithExpiry,
// AssignMachineRole, RemoveProjectMember, RemoveUserRole) a local backend would
// use, unconditionally — for every caller, node-typed or not — so their real
// ceiling checks always run.
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
// One exception with its own atomicity story: RemoveGlobalAdminRoleGuardedProxy
// calls core.RemoveUserRole rather than a plain passthrough — not because
// that's this server's OWN policy decision, but because no real transaction
// can span the HTTP hop back to the calling server (RemoteStorage.
// WithTransaction is a no-op passthrough), so whichever server ultimately owns
// the row is the only one that CAN enforce the last-global-admin invariant
// atomically. See the storage.Storage interface doc (internal/core/storage/
// interface.go) and internal/core/rbac_management.go's RemoveUserRole doc for
// the full reasoning — the same pattern CreateSecretDependencyExclusiveProxy
// (#260) and AdvanceWebAuthnCredentialCounterProxy (#306/#517) already
// established for their own TOCTOU classes. The atomicity claim was always
// true, but it originally said nothing about WHO may invoke the removal — a
// caller now needs roles.assign at global scope (matching the human-facing
// DELETE /api/v1/user-roles gate), enforced unconditionally since ADR-085.
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
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/keyorixhq/keyorix/internal/core"
	coreStorage "github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/server/middleware"
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
// system.write holder, human or machine — reaching global admin. #1552
// (closed by ADR-085, 2026-08-25): a genuine node-credential relay used to be
// trusted to have already run that ceiling locally against the real acting
// human, on the theory that a node credential relays an already-authorized
// downstream decision. ADR-085 found that topology cannot exist in this
// codebase (ADR-083's validateRemoteStorageNotServer rejects storage.type:
// remote for any server process) and removed the node-credential exemption
// entirely — every caller, node-typed or not, now routes through
// core.AssignUserRoleWithExpiry, running the real ceiling against its OWN
// authority.
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
	err := h.coreService.AssignUserRoleWithExpiry(r.Context(), actorID(r), body.UserID, body.RoleID, scope, body.ExpiresAt, isMachineActor(r))
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
	if err := h.coreService.AssignGroupRoleWithExpiry(r.Context(), actorID(r), body.GroupID, body.RoleID, scope, body.ExpiresAt, isMachineActor(r)); err != nil {
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

// removeGlobalAdminRoleGuardedProxyWire is the request body for
// RemoveGlobalAdminRoleGuardedProxy. AdminRoleIDs is accepted for wire
// compatibility with older RemoteStorage clients but is IGNORED and unused —
// ADR-085 (2026-08-25) removed the last raw storage.RemoveGlobalAdminRoleGuarded
// call this field ever fed (the node-credential branch); every caller now goes
// through core.RemoveUserRole, which resolves the install-admin-role set itself
// (installAdminRoleIDSet, rbac_management.go) and never trusts a caller-supplied
// set for the last-admin count (the original #G79 concern this field's
// resolution logic existed to close).
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
// the storage.Storage interface doc for the atomic last-global-admin invariant
// this preserves across the HTTP hop.
//
// Found during the G80 documented-exception re-verification sweep, same shape
// as CreateMachineIdentityCredentialProxy/CreateOIDCBindingProxy: the atomicity
// of the guard was never in question, but the package doc's "deliberate
// exception" reasoning only defended THAT — it never argued who is allowed to
// invoke the removal at all, and the raw call had no actor check of any kind.
// The human-facing equivalent (DELETE /api/v1/user-roles) is gated on
// roles.assign AT THE TARGET SCOPE (router.go's user-roles route, #342); this
// route's own gate was only system.write, materially weaker and, per
// auth_bootstrap.go's own doc, granted for unrelated reasons (audit
// checkpoints, legal holds, SoD policies) — a system.write-only caller with no
// roles.assign, or a bare node credential, could strip a named admin's
// global-admin role with no audit trail. Every caller is now routed through
// core.RemoveUserRole after an explicit roles.assign-at-global-scope check
// (mirroring the human-facing gate), which also closes the missing-audit-event
// gap for free (RemoveUserRole calls LogRoleRemoved + evictUserSessionCache).
// A node-credential relay used to be trusted unconditionally here — ADR-085
// (Accepted, 2026-08-25) found no live caller for that exemption anywhere and
// removed it; a node credential now needs the same roles.assign grant as any
// other caller, closing this CLEAN (not half).
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

	userCtx := middleware.GetUserFromContext(r.Context())
	if userCtx == nil {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN",
			"removing a global-admin role grant requires the roles.assign permission at global scope")
		return
	}
	if ok, aerr := h.coreService.AuthorizePrincipal(r.Context(), userCtx.ActorKind(), userCtx.PrincipalID(), "roles.assign", coreStorage.Scope{}); aerr != nil || !ok {
		writeRemoteAPIError(w, http.StatusForbidden, "FORBIDDEN",
			"removing a global-admin role grant requires the roles.assign permission at global scope")
		return
	}
	err := h.coreService.RemoveUserRole(r.Context(), actorID(r), body.UserID, body.RoleID, coreStorage.Scope{})
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
