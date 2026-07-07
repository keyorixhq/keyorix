// remote_rbac.go — Role and RBAC operations for RemoteStorage.
//
// Covers: CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//
//	AssignRole, RemoveRole, GetUserRoles, GetUserPermissions,
//	CreatePermission, AssignPermissionToRole,
//	ListPermissions, GetPermission, GetRolePermissions (#526),
//	Project/Environment catalog CRUD (proxied over HTTP, #528 — see
//	server/http/handlers/project_catalog_proxy.go and environment_catalog_proxy.go).
//
// For the local (GORM) equivalent see local_rbac.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Roles ---

// CreateRole creates a new role via remote API.
func (rs *RemoteStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/roles", role)
	if err != nil {
		return nil, fmt.Errorf("failed to create role: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create role failed: %s", resp.Error.Error())
	}
	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetRole retrieves a role by ID via remote API.
func (rs *RemoteStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get role failed: %s", resp.Error.Error())
	}
	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetRoleByName retrieves a role by name via remote API.
//
// The server registers this lookup as GET /api/v1/roles/by-name with the name as
// a query parameter (mirroring GetSecretByName's #497 / GetUserByEmail's #503
// query-scoped convention), not as a path segment (#512: an earlier version of
// this method requested /api/v1/roles/by-name/{name}, a route
// server/http/router.go never registered, so every call 404'd against a real
// server regardless of whether the role existed — blocking InviteToProject for
// EVERY role, not just admin roles, under storage.type: remote).
func (rs *RemoteStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/by-name?name=%s", url.QueryEscape(name))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get role by name: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get role by name failed: %s", resp.Error.Error())
	}
	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// UpdateRole updates an existing role via remote API.
func (rs *RemoteStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/%d", role.ID)
	resp, err := rs.client.Put(ctx, path, role)
	if err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update role failed: %s", resp.Error.Error())
	}
	var result models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// DeleteRole deletes a role via remote API.
func (rs *RemoteStorage) DeleteRole(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/roles/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete role failed: %s", resp.Error.Error())
	}
	return nil
}

// ListRoles lists all roles via remote API.
func (rs *RemoteStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/roles")
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list roles failed: %s", resp.Error.Error())
	}
	var result []*models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// --- RBAC assignment ---

// AssignRole assigns a role to a user at scope via remote API.
func (rs *RemoteStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	payload := map[string]uint{
		"user_id":        userID,
		"role_id":        roleID,
		"project_id":     scope.ProjectID,
		"environment_id": scope.EnvironmentID,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/assign-role", payload)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign role failed: %s", resp.Error.Error())
	}
	return nil
}

// GetGroupRoleGrants is a confirmed genuine gap (round 119 completeness
// audit), not the "HTTP handler reads it from local storage instead" claim
// this comment previously made — GetGroupRoles (server/http/handlers/rbac.go)
// calls THIS method, not a different one. Tracked in
// docs/security/HARDENING-BACKLOG.md; see remote_unsupported_completeness_test.go.
func (rs *RemoteStorage) GetGroupRoleGrants(_ context.Context, _ uint) ([]*storage.GroupRoleGrant, error) {
	return nil, remoteUnsupported("GetGroupRoleGrants")
}

// AssignRoleWithExpiry is server-side only (the JIT grant happens during access-
// request approval on the server); not driven over the remote client.
func (rs *RemoteStorage) AssignRoleWithExpiry(_ context.Context, _, _ uint, _ storage.Scope, _ time.Time) error {
	return remoteUnsupported("AssignRoleWithExpiry")
}

// AssignRoleToGroupWithExpiry is server-side only; see AssignRoleWithExpiry.
func (rs *RemoteStorage) AssignRoleToGroupWithExpiry(_ context.Context, _, _ uint, _ storage.Scope, _ time.Time) error {
	return remoteUnsupported("AssignRoleToGroupWithExpiry")
}

// DeleteExpiredRoleGrants proxies onto POST
// /api/v1/system/retention/role-grants/purge-expired
// (server/http/handlers/retention_proxy.go, finding #520) — the SAME
// "RemoteStorage stub -> thin proxy route" pattern established for login-attempts
// (#452). Returns the full removed storage.RoleAssignment rows, not just a
// count: the calling server's own internal/core.RemoveExpiredRoleGrants writes
// one role.expired audit event per grant using exactly this data, which a bare
// count could not reconstruct. storage.RoleAssignment already carries full
// snake_case json tags, so no separate wire DTO is needed on either side.
func (rs *RemoteStorage) DeleteExpiredRoleGrants(ctx context.Context, before time.Time) ([]storage.RoleAssignment, error) {
	body := struct {
		Before time.Time `json:"before"`
	}{Before: before}
	resp, err := rs.client.Post(ctx, "/api/v1/system/retention/role-grants/purge-expired", body)
	if err != nil {
		return nil, fmt.Errorf("failed to purge expired role grants: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("purge expired role grants failed: %s", resp.Error.Error())
	}
	var result struct {
		Removed []storage.RoleAssignment `json:"removed"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Removed, nil
}

// RemoveRole removes a role from a user at scope via remote API.
func (rs *RemoteStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	payload := map[string]uint{
		"user_id":        userID,
		"role_id":        roleID,
		"project_id":     scope.ProjectID,
		"environment_id": scope.EnvironmentID,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/remove-role", payload)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove role failed: %s", resp.Error.Error())
	}
	return nil
}

// RemoveAllProjectRoleGrants is a server-internal RBAC primitive (project
// membership management runs entirely against LocalStorage); unsupported here.
func (rs *RemoteStorage) RemoveAllProjectRoleGrants(_ context.Context, _, _ uint) error {
	return remoteUnsupported("RemoveAllProjectRoleGrants")
}

// GetUserRoles retrieves all roles for a user via remote API.
func (rs *RemoteStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	path := fmt.Sprintf("/api/v1/users/%d/roles", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user roles failed: %s", resp.Error.Error())
	}
	var result []*models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetUserPermissions retrieves all permissions for a user via remote API.
func (rs *RemoteStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	path := fmt.Sprintf("/api/v1/users/%d/permissions", userID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get user permissions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get user permissions failed: %s", resp.Error.Error())
	}
	var result []*storage.Permission
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// GetUserGroupPermissions is not supported in remote storage. SoD conflict
// detection (its only caller) runs server-side against LocalStorage, which resolves
// group-inherited permissions directly; there is no remote API for it. Fail loudly
// rather than silently under-reporting, in case a future caller wires it up.
func (rs *RemoteStorage) GetUserGroupPermissions(_ context.Context, _ uint) ([]*storage.Permission, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// --- Permission management (not supported in remote mode) ---

// CreatePermission is not supported in remote storage.
func (rs *RemoteStorage) CreatePermission(_ context.Context, _ *models.Permission) (*models.Permission, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// AssignPermissionToRole is not supported in remote storage.
func (rs *RemoteStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return fmt.Errorf("not supported in remote storage")
}

// ListPermissions lists the full permission catalog via remote API. #526: the
// permission catalog is a near-static, seeded-not-created-dynamically read —
// RemoteStorage has no local database to fall back on, so a spoke server's
// catalog view (and everything that depends on it) was 100% broken. Reuses
// the EXISTING human-facing GET /api/v1/permissions route
// (server/http/router.go, roles.read-gated), same as the interactive UI —
// no new route needed. The handler wraps the list in {"permissions":...,
// "total":...} (server/http/handlers/rbac.go's ListPermissions), so this
// unmarshals into that shape rather than a bare array.
func (rs *RemoteStorage) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/permissions")
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list permissions failed: %s", resp.Error.Error())
	}
	var result struct {
		Permissions []*models.Permission `json:"permissions"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Permissions, nil
}

// GetPermission retrieves a single permission by ID via remote API. #526:
// AssignPermissionToRole (internal/core/rbac_management.go) calls this first
// to resolve permissionID -> name for the #169 self-permission-check before
// assigning — with no local DB, this was an unconditional stub, so assigning
// a permission to a role hard-failed under storage.type: remote. Unlike
// ListPermissions/GetRolePermissions, no existing route covered a per-ID
// permission lookup, so this adds GET /api/v1/permissions/{id}
// (server/http/router.go, server/http/handlers/rbac.go's new GetPermission
// handler) as a sibling of the existing GET /api/v1/permissions collection,
// gated by the SAME roles.read — a caller who can already enumerate every
// permission via ListPermissions gains no new capability by looking one up
// individually. Mirrors GetRoleByName's bare-object response shape (not
// wrapped), since the new handler was written to return the permission
// directly.
func (rs *RemoteStorage) GetPermission(ctx context.Context, id uint) (*models.Permission, error) {
	path := fmt.Sprintf("/api/v1/permissions/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get permission failed: %s", resp.Error.Error())
	}
	var result models.Permission
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// GetRolePermissions retrieves a role's assigned permissions via remote API.
// #526: real callers span the role-permission view (GetRoleWithPermissions),
// requireGranterHoldsRolePermissions's grant-time admin-rank-ceiling check
// (authz.go), and several read-only RBAC-dependent reports — access reviews
// (access_review.go), compliance posture's dormant-admin-tier-grant scan
// (compliance_posture.go), and SoD conflict detection (sod.go) — all broken
// with no local DB fallback. Reuses the EXISTING human-facing
// GET /api/v1/roles/{id}/permissions route (server/http/router.go,
// roles.read-gated), same as the interactive UI. Confirmed read-only: every
// caller either renders a view or feeds a report; the one authorization use
// (requireGranterHoldsRolePermissions) reads the role's CURRENT permission
// bundle to check the actor's own standing authority, not as one half of a
// check-then-act mutation on the bundle itself — the same sequential-read
// exposure already exists for LocalStorage's two plain (non-transactional)
// DB calls, so proxying over HTTP (RemoteStorage.WithTransaction is a no-op
// passthrough) introduces no NEW atomicity gap. The handler wraps the list in
// {"role_id":...,"role_name":...,"permissions":...} (server/http/handlers/
// rbac.go's GetRolePermissions), so this unmarshals into that shape rather
// than a bare array.
func (rs *RemoteStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	path := fmt.Sprintf("/api/v1/roles/%d/permissions", roleID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get role permissions failed: %s", resp.Error.Error())
	}
	var result struct {
		Permissions []*models.Permission `json:"permissions"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Permissions, nil
}

// RemovePermissionFromRole revokes a permission from a role via the REST API.
func (rs *RemoteStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error {
	resp, err := rs.client.Delete(ctx, fmt.Sprintf("/api/v1/roles/%d/permissions/%d", roleID, permissionID))
	if err != nil {
		return fmt.Errorf("failed to remove permission from role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove permission from role failed: %s", resp.Error.Error())
	}
	return nil
}

// Keyorix Connect per-reference grants (ADR-045) — backlog #527. This doc comment
// PREVIOUSLY claimed these four primitives were a server-side-only concern because
// "the live federated-read path and grant management both run against LocalStorage,
// so the remote (client) storage does not proxy these primitives." That claim was
// wrong: a downstream Keyorix server booted with storage.type: remote (ADR-049) runs
// the SAME core.KeyorixCore as any other node, and ReadFederatedSecret (the HTTP
// GetSecret handler and gRPC ConnectService.ReadSecret both call it unconditionally)
// calls connectRefAllowed, which calls ListConnectRefGrantsByConnector on EVERY
// federated read regardless of whether the connector actually has any ref-grants.
// Before this fix, that stub's error made connectRefAllowed fail closed, so EVERY
// Keyorix Connect read failed on EVERY connector on any storage.type: remote node
// with Connect configured — not a hub-only feature at all. These are now thin
// passthroughs onto four new routes under /api/v1/system/connect-grants
// (server/http/handlers/connect_grants_proxy.go), following the EXACT #510
// setup-token-proxy pattern: gated on the same system.read/system.write tier a
// RemoteStorage credential already needs for every other proxied call — no new
// privilege class — and making NO Connect POLICY decision here (role resolution,
// prefix/glob matching, expiry) — that all stays in the CALLING server's own
// internal/core/connect.go, exactly as it does against a local backend.
func (rs *RemoteStorage) ListConnectRefGrantsByConnector(ctx context.Context, connector string) ([]*models.ConnectRefGrant, error) {
	path := "/api/v1/system/connect-grants/by-connector/" + url.PathEscape(connector)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list connect ref-grants by connector: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list connect ref-grants by connector failed: %s", resp.Error.Error())
	}
	var wire []connectRefGrantWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return connectRefGrantsFromWire(wire), nil
}

// ListConnectRefGrants lists every per-reference grant via remote API — see the
// package doc above (backlog #527) for why this is genuinely reachable under
// storage.type: remote.
func (rs *RemoteStorage) ListConnectRefGrants(ctx context.Context) ([]*models.ConnectRefGrant, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/connect-grants")
	if err != nil {
		return nil, fmt.Errorf("failed to list connect ref-grants: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list connect ref-grants failed: %s", resp.Error.Error())
	}
	var wire []connectRefGrantWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return connectRefGrantsFromWire(wire), nil
}

// CreateConnectRefGrant creates a per-reference grant via remote API — see the
// package doc above (backlog #527).
func (rs *RemoteStorage) CreateConnectRefGrant(ctx context.Context, g *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	resp, err := rs.client.Post(ctx, "/api/v1/system/connect-grants", newConnectRefGrantWire(g))
	if err != nil {
		return nil, fmt.Errorf("failed to create connect ref-grant: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("create connect ref-grant failed: %s", resp.Error.Error())
	}
	var wire connectRefGrantWire
	if err := json.Unmarshal(resp.Data, &wire); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return wire.toModel(), nil
}

// DeleteConnectRefGrant deletes a per-reference grant by id via remote API — see the
// package doc above (backlog #527).
func (rs *RemoteStorage) DeleteConnectRefGrant(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/connect-grants/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete connect ref-grant: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete connect ref-grant failed: %s", resp.Error.Error())
	}
	return nil
}

// connectRefGrantWire mirrors models.ConnectRefGrant's fields exactly (snake_case) —
// the wire shape server/http/handlers/connect_grants_proxy.go sends/expects, mirroring
// remote_auth.go's setupTokenWire pattern (#510).
type connectRefGrantWire struct {
	ID        uint       `json:"id"`
	RoleID    uint       `json:"role_id"`
	Connector string     `json:"connector"`
	RefPrefix string     `json:"ref_prefix"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
}

func newConnectRefGrantWire(g *models.ConnectRefGrant) connectRefGrantWire {
	return connectRefGrantWire{
		ID:        g.ID,
		RoleID:    g.RoleID,
		Connector: g.Connector,
		RefPrefix: g.RefPrefix,
		ExpiresAt: g.ExpiresAt,
		CreatedAt: g.CreatedAt,
	}
}

func (w connectRefGrantWire) toModel() *models.ConnectRefGrant {
	return &models.ConnectRefGrant{
		ID:        w.ID,
		RoleID:    w.RoleID,
		Connector: w.Connector,
		RefPrefix: w.RefPrefix,
		ExpiresAt: w.ExpiresAt,
		CreatedAt: w.CreatedAt,
	}
}

func connectRefGrantsFromWire(wire []connectRefGrantWire) []*models.ConnectRefGrant {
	out := make([]*models.ConnectRefGrant, 0, len(wire))
	for _, w := range wire {
		out = append(out, w.toModel())
	}
	return out
}

// GetGroupRoles lists the roles assigned to a group via remote API.
func (rs *RemoteStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	path := fmt.Sprintf("/api/v1/groups/%d/roles", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get group roles: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get group roles failed: %s", resp.Error.Error())
	}
	var result []*models.Role
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListGroupRoleAssignments is not supported in remote storage — the client reaches
// group role state through GetGroupRoles/GetGroupRoleGrants (per-group, scope-less)
// via their REST endpoints; there is no all-scope listing endpoint to proxy to.
func (rs *RemoteStorage) ListGroupRoleAssignments(_ context.Context, _ uint) ([]storage.RoleAssignment, error) {
	return nil, remoteUnsupported("ListGroupRoleAssignments")
}

// AssignRoleToGroup assigns a role to a group at scope via remote API.
func (rs *RemoteStorage) AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	path := fmt.Sprintf("/api/v1/groups/%d/roles", groupID)
	payload := map[string]uint{
		"role_id":        roleID,
		"project_id":     scope.ProjectID,
		"environment_id": scope.EnvironmentID,
	}
	resp, err := rs.client.Post(ctx, path, payload)
	if err != nil {
		return fmt.Errorf("failed to assign role to group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign role to group failed: %s", resp.Error.Error())
	}
	return nil
}

// RemoveRoleFromGroup removes a role from a group via remote API.
func (rs *RemoteStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, _ storage.Scope) error {
	path := fmt.Sprintf("/api/v1/groups/%d/roles/%d", groupID, roleID)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to remove role from group: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove role from group failed: %s", resp.Error.Error())
	}
	return nil
}

// GetUserRoleIDsAt is a server-internal authorization primitive; remote clients
// do not enforce, so it is unsupported here.
func (rs *RemoteStorage) GetUserRoleIDsAt(_ context.Context, _ uint, _ storage.Scope) ([]uint, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// GetUserRoleIDsExact is a server-internal authorization primitive.
func (rs *RemoteStorage) GetUserRoleIDsExact(_ context.Context, _ uint, _ storage.Scope) ([]uint, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) IsProjectMember(_ context.Context, _ uint, _ uint) (bool, error) {
	return false, fmt.Errorf("not supported in remote storage")
}

// GetUserGroupRoleIDsAt is a server-internal authorization primitive.
func (rs *RemoteStorage) GetUserGroupRoleIDsAt(_ context.Context, _ uint, _ storage.Scope) ([]uint, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// GetUserRoleScopes is a server-internal authorization primitive.
func (rs *RemoteStorage) GetUserRoleScopes(_ context.Context, _ uint) ([]storage.Scope, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// RoleSetHasPermission is a server-internal authorization primitive.
func (rs *RemoteStorage) RoleSetHasPermission(_ context.Context, _ []uint, _ string) (bool, error) {
	return false, fmt.Errorf("not supported in remote storage")
}

// --- Project / Environment ---
//
// CreateProject/CreateEnvironment remain deliberately unsupported (below); every
// OTHER project/environment catalog method is proxied over HTTP (#528) to
// server/http/handlers/project_catalog_proxy.go and environment_catalog_proxy.go's
// /api/v1/system/projects* and /api/v1/system/environments* routes — thin
// passthroughs onto the SAME storage.Storage primitives internal/core/catalog.go
// already uses against a local backend. See those handler files' package docs for
// the reuse-vs-new-route rationale (why the human-facing /api/v1/projects routes are
// NOT reused as the proxy target).

func (rs *RemoteStorage) CreateProject(_ context.Context, _ *models.Project) (*models.Project, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateEnvironment(_ context.Context, _ *models.Environment) (*models.Environment, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// projectWire mirrors models.Project's fields exactly (snake_case) — the wire shape
// project_catalog_proxy.go's projectProxyWire sends/expects.
type projectWire struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	RequireMFA  bool       `json:"require_mfa"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"deleted_at,omitempty"`
}

func (w projectWire) toModel() *models.Project {
	p := &models.Project{
		ID:          w.ID,
		Name:        w.Name,
		Description: w.Description,
		RequireMFA:  w.RequireMFA,
		CreatedAt:   w.CreatedAt,
		UpdatedAt:   w.UpdatedAt,
	}
	if w.DeletedAt != nil {
		p.DeletedAt.Time = *w.DeletedAt
		p.DeletedAt.Valid = true
	}
	return p
}

func newProjectWire(p *models.Project) projectWire {
	w := projectWire{
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

func decodeProjectResponse(data json.RawMessage) (*models.Project, error) {
	var w projectWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return w.toModel(), nil
}

// ListProjects lists every project via GET /api/v1/system/projects.
func (rs *RemoteStorage) ListProjects(ctx context.Context) ([]*models.Project, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/projects")
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list projects failed: %s", resp.Error.Error())
	}
	var result struct {
		Projects []projectWire `json:"projects"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	projects := make([]*models.Project, 0, len(result.Projects))
	for _, w := range result.Projects {
		projects = append(projects, w.toModel())
	}
	return projects, nil
}

// ListProjectsWithCounts lists every project with secret/environment counts via GET
// /api/v1/system/projects/with-counts?include_deleted=.
func (rs *RemoteStorage) ListProjectsWithCounts(ctx context.Context, includeDeleted bool) ([]storage.ProjectWithCounts, error) {
	path := fmt.Sprintf("/api/v1/system/projects/with-counts?include_deleted=%t", includeDeleted)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects with counts: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list projects with counts failed: %s", resp.Error.Error())
	}
	var result struct {
		Projects []storage.ProjectWithCounts `json:"projects"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Projects, nil
}

// GetProject retrieves a project by ID via GET /api/v1/system/projects/{id}.
func (rs *RemoteStorage) GetProject(ctx context.Context, id uint) (*models.Project, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get project: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get project failed: %s", resp.Error.Error())
	}
	return decodeProjectResponse(resp.Data)
}

// UpdateProject updates an existing project via PUT /api/v1/system/projects/{id}.
func (rs *RemoteStorage) UpdateProject(ctx context.Context, project *models.Project) (*models.Project, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d", project.ID)
	resp, err := rs.client.Put(ctx, path, newProjectWire(project))
	if err != nil {
		return nil, fmt.Errorf("failed to update project: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("update project failed: %s", resp.Error.Error())
	}
	return decodeProjectResponse(resp.Data)
}

// DeleteProject cascade-deletes a project (unconditionally — no empty-project guard)
// via DELETE /api/v1/system/projects/{id}. This backs the force=true path; the
// force=false guard+cascade is DeleteProjectIfEmpty below.
func (rs *RemoteStorage) DeleteProject(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/projects/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete project: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete project failed: %s", resp.Error.Error())
	}
	return nil
}

// DeleteProjectIfEmpty is the atomic guard+cascade form of DeleteProject(force=false)
// (#528), proxied as ONE HTTP call to POST
// /api/v1/system/projects/{id}/delete-if-empty — see the storage.Storage interface
// doc comment on this method for the full TOCTOU rationale this closes relative to a
// naive two-call (count, then delete) proxy.
func (rs *RemoteStorage) DeleteProjectIfEmpty(ctx context.Context, id uint) (int, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d/delete-if-empty", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to delete project if empty: %w", err)
	}
	if !resp.Success {
		return 0, fmt.Errorf("delete project if empty failed: %s", resp.Error.Error())
	}
	var result struct {
		BlockingSecretCount int `json:"blocking_secret_count"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.BlockingSecretCount, nil
}

// RestoreProject reverses a project soft-delete (and its cascade) via POST
// /api/v1/system/projects/{id}/restore.
func (rs *RemoteStorage) RestoreProject(ctx context.Context, id uint) (int, int, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d/restore", id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to restore project: %w", err)
	}
	if !resp.Success {
		return 0, 0, fmt.Errorf("restore project failed: %s", resp.Error.Error())
	}
	var result struct {
		RestoredEnvironments int `json:"restored_environments"`
		RestoredSecrets      int `json:"restored_secrets"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return 0, 0, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.RestoredEnvironments, result.RestoredSecrets, nil
}

// environmentWire mirrors models.Environment's fields exactly (snake_case) — the
// wire shape environment_catalog_proxy.go's environmentProxyWire sends/expects.
type environmentWire struct {
	ID        uint       `json:"id"`
	ProjectID uint       `json:"project_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

func (w environmentWire) toModel() *models.Environment {
	e := &models.Environment{
		ID:        w.ID,
		ProjectID: w.ProjectID,
		Name:      w.Name,
		CreatedAt: w.CreatedAt,
		UpdatedAt: w.UpdatedAt,
	}
	if w.DeletedAt != nil {
		e.DeletedAt.Time = *w.DeletedAt
		e.DeletedAt.Valid = true
	}
	return e
}

func decodeEnvironmentResponse(data json.RawMessage) (*models.Environment, error) {
	var w environmentWire
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return w.toModel(), nil
}

// ListEnvironments lists every environment via GET /api/v1/system/environments.
func (rs *RemoteStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/system/environments")
	if err != nil {
		return nil, fmt.Errorf("failed to list environments: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list environments failed: %s", resp.Error.Error())
	}
	var result struct {
		Environments []environmentWire `json:"environments"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	environments := make([]*models.Environment, 0, len(result.Environments))
	for _, w := range result.Environments {
		environments = append(environments, w.toModel())
	}
	return environments, nil
}

// listEnvironmentsByProject is the shared implementation behind
// ListEnvironmentsByProject/ListEnvironmentsByProjectIncludingDeleted via GET
// /api/v1/system/projects/{id}/environments?include_deleted=.
func (rs *RemoteStorage) listEnvironmentsByProject(ctx context.Context, projectID uint, includeDeleted bool) ([]*models.Environment, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d/environments?include_deleted=%t", projectID, includeDeleted)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list environments by project: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list environments by project failed: %s", resp.Error.Error())
	}
	var result struct {
		Environments []environmentWire `json:"environments"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	environments := make([]*models.Environment, 0, len(result.Environments))
	for _, w := range result.Environments {
		environments = append(environments, w.toModel())
	}
	return environments, nil
}

func (rs *RemoteStorage) ListEnvironmentsByProject(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return rs.listEnvironmentsByProject(ctx, projectID, false)
}

// ListEnvironmentsByProjectIncludingDeleted is like ListEnvironmentsByProject but
// also returns soft-deleted environments, for the restore UI.
func (rs *RemoteStorage) ListEnvironmentsByProjectIncludingDeleted(ctx context.Context, projectID uint) ([]*models.Environment, error) {
	return rs.listEnvironmentsByProject(ctx, projectID, true)
}

// GetEnvironment retrieves an environment by ID via GET
// /api/v1/system/environments/{id}.
//
// #499 carve-out (untouched by #528): CreateSecret's own call site
// (internal/core/secrets.go) special-cases errors.Is(ErrUnsupportedByBackend) to skip
// its ownership pre-check when this was unsupported. Now that it's proxied for real,
// that pre-check simply starts running for real too — no change was needed there.
func (rs *RemoteStorage) GetEnvironment(ctx context.Context, id uint) (*models.Environment, error) {
	path := fmt.Sprintf("/api/v1/system/environments/%d", id)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get environment: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get environment failed: %s", resp.Error.Error())
	}
	return decodeEnvironmentResponse(resp.Data)
}

// DeleteEnvironment deletes an environment (refusing if it still has active secrets)
// via DELETE /api/v1/system/environments/{id}.
func (rs *RemoteStorage) DeleteEnvironment(ctx context.Context, id uint) error {
	path := fmt.Sprintf("/api/v1/system/environments/%d", id)
	resp, err := rs.client.Delete(ctx, path)
	if err != nil {
		return fmt.Errorf("failed to delete environment: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete environment failed: %s", resp.Error.Error())
	}
	return nil
}

// RestoreEnvironment reverses a soft-delete, scoped to projectID, via POST
// /api/v1/system/projects/{projectId}/environments/{id}/restore.
func (rs *RemoteStorage) RestoreEnvironment(ctx context.Context, projectID, id uint) error {
	path := fmt.Sprintf("/api/v1/system/projects/%d/environments/%d/restore", projectID, id)
	resp, err := rs.client.Post(ctx, path, nil)
	if err != nil {
		return fmt.Errorf("failed to restore environment: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("restore environment failed: %s", resp.Error.Error())
	}
	return nil
}

// ListProjectMembers lists a project's user members via GET
// /api/v1/system/projects/{id}/members.
func (rs *RemoteStorage) ListProjectMembers(ctx context.Context, projectID uint) ([]storage.ProjectMember, error) {
	path := fmt.Sprintf("/api/v1/system/projects/%d/members", projectID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list project members: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list project members failed: %s", resp.Error.Error())
	}
	var result struct {
		Members []storage.ProjectMember `json:"members"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.Members, nil
}

func (rs *RemoteStorage) ListProjectRoleAssignments(_ context.Context, _ uint) ([]storage.RoleAssignment, error) {
	return nil, remoteUnsupported("ListProjectRoleAssignments")
}

func (rs *RemoteStorage) ListProjectMachineRoleAssignments(_ context.Context, _ uint) ([]storage.RoleAssignment, error) {
	return nil, remoteUnsupported("ListProjectMachineRoleAssignments")
}

// ListGlobalAdminAssignmentsForUpdate is a server-internal RBAC primitive backing
// the last-admin-removal guard's atomicity fix (#340); like
// ListProjectRoleAssignments, RBAC admin-removal guarding runs entirely against
// LocalStorage server-side, so this is unsupported here.
func (rs *RemoteStorage) ListGlobalAdminAssignmentsForUpdate(_ context.Context, _ []uint) ([]storage.RoleAssignment, error) {
	return nil, remoteUnsupported("ListGlobalAdminAssignmentsForUpdate")
}
