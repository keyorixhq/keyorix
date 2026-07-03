// remote_rbac.go — Role and RBAC operations for RemoteStorage.
//
// Covers: CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//
//	AssignRole, RemoveRole, GetUserRoles, CheckPermission, GetUserPermissions,
//	CreatePermission, AssignPermissionToRole,
//	Project/Environment stubs.
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
func (rs *RemoteStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	path := fmt.Sprintf("/api/v1/roles/by-name/%s", url.PathEscape(name))
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

// GetGroupRoleGrants is server-side only (the HTTP handler reads it from local
// storage); the remote client uses GetGroupRoles for the role list.
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

// DeleteExpiredRoleGrants is server-side only (run by the expiry scheduler).
func (rs *RemoteStorage) DeleteExpiredRoleGrants(_ context.Context, _ time.Time) ([]storage.RoleAssignment, error) {
	return nil, remoteUnsupported("DeleteExpiredRoleGrants")
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

// CheckPermission checks if a user has a specific resource/action permission via remote API.
func (rs *RemoteStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	path := fmt.Sprintf("/api/v1/rbac/check-permission?user_id=%d&resource=%s&action=%s", userID, url.QueryEscape(resource), url.QueryEscape(action))
	resp, err := rs.client.Get(ctx, path)
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	if !resp.Success {
		return false, fmt.Errorf("check permission failed: %s", resp.Error.Error())
	}
	var result struct {
		HasPermission bool `json:"has_permission"`
	}
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return false, fmt.Errorf("failed to parse response: %w", err)
	}
	return result.HasPermission, nil
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

// Keyorix Connect per-reference grants (ADR-045) are a server-side concern: the live
// federated-read path and grant management both run against LocalStorage, so the
// remote (client) storage does not proxy these primitives.

// ListConnectRefGrantsByConnector is not supported in remote storage.
func (rs *RemoteStorage) ListConnectRefGrantsByConnector(_ context.Context, _ string) ([]*models.ConnectRefGrant, error) {
	return nil, remoteUnsupported("ListConnectRefGrantsByConnector")
}

// ListConnectRefGrants is not supported in remote storage.
func (rs *RemoteStorage) ListConnectRefGrants(_ context.Context) ([]*models.ConnectRefGrant, error) {
	return nil, remoteUnsupported("ListConnectRefGrants")
}

// CreateConnectRefGrant is not supported in remote storage.
func (rs *RemoteStorage) CreateConnectRefGrant(_ context.Context, _ *models.ConnectRefGrant) (*models.ConnectRefGrant, error) {
	return nil, remoteUnsupported("CreateConnectRefGrant")
}

// DeleteConnectRefGrant is not supported in remote storage.
func (rs *RemoteStorage) DeleteConnectRefGrant(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteConnectRefGrant")
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

func (rs *RemoteStorage) GetEnvironment(_ context.Context, _ uint) (*models.Environment, error) {
	return nil, remoteUnsupported("GetEnvironment")
}

func (rs *RemoteStorage) DeleteEnvironment(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteEnvironment")
}

func (rs *RemoteStorage) RestoreEnvironment(_ context.Context, _, _ uint) error {
	return remoteUnsupported("RestoreEnvironment")
}
