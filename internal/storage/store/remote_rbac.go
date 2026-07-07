// remote_rbac.go — Role and RBAC operations for RemoteStorage.
//
// Covers: CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//
//	AssignRole, RemoveRole, GetUserRoles, GetUserPermissions,
//	CreatePermission, AssignPermissionToRole,
//	Project/Environment stubs.
//
// For the local (GORM) equivalent see local_rbac.go.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/remote"
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

// GetGroupRoleGrants is a thin passthrough onto GET
// /api/v1/system/rbac/groups/{groupID}/role-grants (finding #525) —
// GetGroupRoles (server/http/handlers/rbac.go) calls THIS method, not a
// different one, so RemoveUserFromGroup/AddUserToGroup and the human-facing
// "group roles" tab were completely non-functional under storage.type: remote
// before this fix. A previous version of this doc comment claimed the HTTP
// handler read this from local storage instead — independently confirmed
// FALSE during the audit that found this gap (round 119 completeness sweep).
func (rs *RemoteStorage) GetGroupRoleGrants(ctx context.Context, groupID uint) ([]*storage.GroupRoleGrant, error) {
	path := fmt.Sprintf("/api/v1/system/rbac/groups/%d/role-grants", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to get group role grants: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get group role grants failed: %s", resp.Error.Error())
	}
	var result []*storage.GroupRoleGrant
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// AssignRoleWithExpiry proxies onto POST /api/v1/system/rbac/assign-role-with-expiry
// (finding #525) — the JIT time-bound grant path (invitations.go's access-request
// TTL approval, jit_access.go's direct grant, break_glass.go's emergency
// activation) was completely non-functional under storage.type: remote before this
// fix. This is a single storage-layer call on either backend (LocalStorage's
// assignUserRole does its own existing-row read/expired-row-replace/create dance
// entirely within ONE Go function, not across a WithTransaction boundary), so one
// HTTP round trip preserves the same atomicity guarantee LocalStorage already has —
// no NEW race is introduced by proxying it, unlike RemoveGlobalAdminRoleGuarded
// below.
func (rs *RemoteStorage) AssignRoleWithExpiry(ctx context.Context, userID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	payload := roleWithExpiryWire{
		UserID: userID, RoleID: roleID,
		ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID,
		ExpiresAt: expiresAt,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/assign-role-with-expiry", payload)
	if err != nil {
		return fmt.Errorf("failed to assign role with expiry: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign role with expiry failed: %s", resp.Error.Error())
	}
	return nil
}

// AssignRoleToGroupWithExpiry proxies onto POST
// /api/v1/system/rbac/assign-role-to-group-with-expiry (finding #525); see
// AssignRoleWithExpiry for the atomicity reasoning (identical single-call shape).
func (rs *RemoteStorage) AssignRoleToGroupWithExpiry(ctx context.Context, groupID, roleID uint, scope storage.Scope, expiresAt time.Time) error {
	payload := roleWithExpiryWire{
		GroupID: groupID, RoleID: roleID,
		ProjectID: scope.ProjectID, EnvironmentID: scope.EnvironmentID,
		ExpiresAt: expiresAt,
	}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/assign-role-to-group-with-expiry", payload)
	if err != nil {
		return fmt.Errorf("failed to assign role to group with expiry: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign role to group with expiry failed: %s", resp.Error.Error())
	}
	return nil
}

// roleWithExpiryWire is the shared wire body for AssignRoleWithExpiry (UserID set,
// GroupID zero) and AssignRoleToGroupWithExpiry (GroupID set, UserID zero) —
// mirrored exactly in server/http/handlers/rbac_role_grants_proxy.go.
type roleWithExpiryWire struct {
	UserID        uint      `json:"user_id,omitempty"`
	GroupID       uint      `json:"group_id,omitempty"`
	RoleID        uint      `json:"role_id"`
	ProjectID     uint      `json:"project_id"`
	EnvironmentID uint      `json:"environment_id"`
	ExpiresAt     time.Time `json:"expires_at"`
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

// RemoveAllProjectRoleGrants proxies onto POST
// /api/v1/system/rbac/remove-all-project-role-grants (finding #525) —
// RemoveProjectMember's bulk-delete step (DELETE /projects/{id}/members/{userId})
// was completely non-functional under storage.type: remote before this fix. A
// single bulk DELETE (no read-check-write sequence), so one HTTP round trip is
// exactly as atomic as the local call.
func (rs *RemoteStorage) RemoveAllProjectRoleGrants(ctx context.Context, userID, projectID uint) error {
	payload := map[string]uint{"user_id": userID, "project_id": projectID}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/remove-all-project-role-grants", payload)
	if err != nil {
		return fmt.Errorf("failed to remove all project role grants: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove all project role grants failed: %s", resp.Error.Error())
	}
	return nil
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

// ListPermissions is not implemented in remote storage.
func (rs *RemoteStorage) ListPermissions(_ context.Context) ([]*models.Permission, error) {
	return nil, remoteUnsupported("ListPermissions")
}

// GetPermission is not implemented in remote storage.
func (rs *RemoteStorage) GetPermission(_ context.Context, _ uint) (*models.Permission, error) {
	return nil, remoteUnsupported("GetPermission")
}

// GetRolePermissions is not implemented in remote storage.
func (rs *RemoteStorage) GetRolePermissions(_ context.Context, _ uint) ([]*models.Permission, error) {
	return nil, remoteUnsupported("GetRolePermissions")
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

// ListGroupRoleAssignments proxies onto GET
// /api/v1/system/rbac/groups/{groupID}/role-assignments (finding #525) —
// AddUserToGroup's escalation-by-proxy ceiling check (requireAuthorityForRole,
// looped over every role the target group holds) was completely non-functional
// under storage.type: remote before this fix, so POST /groups/{id}/members either
// failed closed (blocking every legitimate group join) or, worse, could not enforce
// the ceiling at all depending on call order — this closes that gap with a genuine
// read.
func (rs *RemoteStorage) ListGroupRoleAssignments(ctx context.Context, groupID uint) ([]storage.RoleAssignment, error) {
	path := fmt.Sprintf("/api/v1/system/rbac/groups/%d/role-assignments", groupID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list group role assignments: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list group role assignments failed: %s", resp.Error.Error())
	}
	var result []storage.RoleAssignment
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
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

// --- Project / Environment (not supported in remote mode) ---

func (rs *RemoteStorage) CreateProject(_ context.Context, _ *models.Project) (*models.Project, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateEnvironment(_ context.Context, _ *models.Environment) (*models.Environment, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) ListProjects(_ context.Context) ([]*models.Project, error) {
	return nil, remoteUnsupported("ListProjects")
}

func (rs *RemoteStorage) ListProjectsWithCounts(_ context.Context, _ bool) ([]storage.ProjectWithCounts, error) {
	return nil, remoteUnsupported("ListProjectsWithCounts")
}

func (rs *RemoteStorage) GetProject(_ context.Context, _ uint) (*models.Project, error) {
	return nil, remoteUnsupported("GetProject")
}

func (rs *RemoteStorage) UpdateProject(_ context.Context, _ *models.Project) (*models.Project, error) {
	return nil, remoteUnsupported("UpdateProject")
}

func (rs *RemoteStorage) DeleteProject(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteProject")
}

func (rs *RemoteStorage) RestoreProject(_ context.Context, _ uint) (int, int, error) {
	return 0, 0, remoteUnsupported("RestoreProject")
}

func (rs *RemoteStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, remoteUnsupported("ListEnvironments")
}

func (rs *RemoteStorage) ListEnvironmentsByProject(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, remoteUnsupported("ListEnvironmentsByProject")
}

func (rs *RemoteStorage) ListEnvironmentsByProjectIncludingDeleted(_ context.Context, _ uint) ([]*models.Environment, error) {
	return nil, remoteUnsupported("ListEnvironmentsByProjectIncludingDeleted")
}

func (rs *RemoteStorage) ListProjectMembers(_ context.Context, _ uint) ([]storage.ProjectMember, error) {
	return nil, remoteUnsupported("ListProjectMembers")
}

// ListProjectRoleAssignments proxies onto GET
// /api/v1/system/rbac/project-role-assignments?project_id=X (finding #525) —
// RemoveProjectMember's audit-trail capture, guardLastProjectAdmin, the access
// review (access_review.go/access_review_revoke.go), catalog.go, compliance
// posture, scim.go, and the global-admin group guards (authz.go, project_id=0)
// all call this; every one of them was completely non-functional under
// storage.type: remote before this fix. A plain read — no read-check-write
// sequence of its own, so a single HTTP round trip introduces no new race.
func (rs *RemoteStorage) ListProjectRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	path := fmt.Sprintf("/api/v1/system/rbac/project-role-assignments?project_id=%d", projectID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list project role assignments: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list project role assignments failed: %s", resp.Error.Error())
	}
	var result []storage.RoleAssignment
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListProjectMachineRoleAssignments proxies onto GET
// /api/v1/system/rbac/project-machine-role-assignments?project_id=X (finding
// #525) — the access review's machine-identity role enumeration
// (access_review.go) was completely non-functional under storage.type: remote
// before this fix.
func (rs *RemoteStorage) ListProjectMachineRoleAssignments(ctx context.Context, projectID uint) ([]storage.RoleAssignment, error) {
	path := fmt.Sprintf("/api/v1/system/rbac/project-machine-role-assignments?project_id=%d", projectID)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list project machine role assignments: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list project machine role assignments failed: %s", resp.Error.Error())
	}
	var result []storage.RoleAssignment
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// ListGlobalAdminAssignmentsForUpdate proxies onto GET
// /api/v1/system/rbac/global-admin-assignments (finding #525) as a PLAIN read —
// like LockMachineIdentityForUpdate/ListSecretDependenciesForProjectForUpdate
// before it, there is no row lock to take over HTTP, so the "ForUpdate" naming is
// aspirational here; safety comes entirely from RemoveGlobalAdminRoleGuarded's
// atomic conditional write below, not from this read. Direct callers of this
// method alone (outside RemoveUserRole's guarded removal path) get the same
// read-only visibility LocalStorage's real row lock would give them anyway on
// SQLite (a plain read); only Postgres HA replication needed the lock, and that's
// entirely a hub-side concern once this method's own caller no longer spans an
// HTTP hop with a subsequent write (see RemoveGlobalAdminRoleGuarded).
func (rs *RemoteStorage) ListGlobalAdminAssignmentsForUpdate(ctx context.Context, adminRoleIDs []uint) ([]storage.RoleAssignment, error) {
	path := "/api/v1/system/rbac/global-admin-assignments?role_ids=" + joinUintsCSV(adminRoleIDs)
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to list global admin assignments: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("list global admin assignments failed: %s", resp.Error.Error())
	}
	var result []storage.RoleAssignment
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return result, nil
}

// removeGlobalAdminRoleGuardedRefusedCode is the machine-readable error code
// RemoveGlobalAdminRoleGuardedProxy returns when the upstream refuses the removal
// (storage.ErrWouldStrandLastAdmin) — mirrored exactly in
// server/http/handlers/rbac_role_grants_proxy.go, the wire-level contract this
// method's error-recovery switch depends on to reconstruct that sentinel on the
// calling side, the same #511-style translation
// CreateSecretDependencyExclusive's duplicate/cycle codes use.
const removeGlobalAdminRoleGuardedRefusedCode = "WOULD_STRAND_LAST_ADMIN"

// RemoveGlobalAdminRoleGuarded proxies onto POST
// /api/v1/system/rbac/global-admin-role/remove-guarded (finding #525) — see the
// Storage interface doc for why this is ONE atomic call rather than a
// ListGlobalAdminAssignmentsForUpdate-then-RemoveRole pair: RemoteStorage.
// WithTransaction is a no-op passthrough, so nothing would otherwise span the
// guard read and the delete across this HTTP hop, reopening the exact
// cross-process last-admin-lockout race #340 closed for HA Postgres replicas —
// this time between concurrent spokes (or a spoke and the hub itself).
func (rs *RemoteStorage) RemoveGlobalAdminRoleGuarded(ctx context.Context, userID, roleID uint, adminRoleIDs []uint) error {
	payload := struct {
		UserID       uint   `json:"user_id"`
		RoleID       uint   `json:"role_id"`
		AdminRoleIDs []uint `json:"admin_role_ids"`
	}{UserID: userID, RoleID: roleID, AdminRoleIDs: adminRoleIDs}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/global-admin-role/remove-guarded", payload)
	if err != nil {
		var httpErr *remote.HTTPError
		if errors.As(err, &httpErr) {
			switch httpErr.ErrorType {
			case removeGlobalAdminRoleGuardedRefusedCode:
				return fmt.Errorf("%w: %s", storage.ErrWouldStrandLastAdmin, httpErr.Message)
			case notAssignedCode:
				return fmt.Errorf("%w: %s", storage.ErrRoleNotAssigned, httpErr.Message)
			}
		}
		return fmt.Errorf("failed to remove global admin role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove global admin role failed: %s", resp.Error.Error())
	}
	return nil
}

// notAssignedCode is the machine-readable error code
// RemoveGlobalAdminRoleGuardedProxy returns when the (userID, roleID) grant does
// not exist (storage.ErrRoleNotAssigned) — mirrored exactly in
// server/http/handlers/rbac_role_grants_proxy.go.
const notAssignedCode = "ROLE_NOT_ASSIGNED"

// joinUintsCSV renders ids as a comma-separated query value (empty string for an
// empty slice), the wire shape RemoveGlobalAdminRoleGuardedProxy's sibling GET
// /api/v1/system/rbac/global-admin-assignments handler parses back with
// strconv.ParseUint per component.
func joinUintsCSV(ids []uint) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatUint(uint64(id), 10))
	}
	return strings.Join(parts, ",")
}

func (rs *RemoteStorage) GetEnvironment(_ context.Context, _ uint) (*models.Environment, error) {
	return nil, remoteUnsupported("GetEnvironment")
}

func (rs *RemoteStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteEnvironment")
}

func (rs *RemoteStorage) RestoreEnvironment(_ context.Context, _, _ uint) error {
	return remoteUnsupported("RestoreEnvironment")
}
