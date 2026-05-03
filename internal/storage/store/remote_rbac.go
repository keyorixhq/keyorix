// remote_rbac.go — Role and RBAC operations for RemoteStorage.
//
// Covers: CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//
//	AssignRole, RemoveRole, GetUserRoles, CheckPermission, GetUserPermissions,
//	CreatePermission, AssignPermissionToRole,
//	Namespace/Zone/Environment stubs.
//
// For the local (GORM) equivalent see local_rbac.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

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
	path := fmt.Sprintf("/api/v1/roles/by-name/%s", name)
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

// AssignRole assigns a role to a user via remote API.
func (rs *RemoteStorage) AssignRole(ctx context.Context, userID, roleID uint) error {
	payload := map[string]uint{"user_id": userID, "role_id": roleID}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/assign-role", payload)
	if err != nil {
		return fmt.Errorf("failed to assign role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("assign role failed: %s", resp.Error.Error())
	}
	return nil
}

// RemoveRole removes a role from a user via remote API.
func (rs *RemoteStorage) RemoveRole(ctx context.Context, userID, roleID uint) error {
	payload := map[string]uint{"user_id": userID, "role_id": roleID}
	resp, err := rs.client.Post(ctx, "/api/v1/rbac/remove-role", payload)
	if err != nil {
		return fmt.Errorf("failed to remove role: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("remove role failed: %s", resp.Error.Error())
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

// CheckPermission checks if a user has a specific resource/action permission via remote API.
func (rs *RemoteStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	path := fmt.Sprintf("/api/v1/rbac/check-permission?user_id=%d&resource=%s&action=%s", userID, resource, action)
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

// --- Permission management (not supported in remote mode) ---

// CreatePermission is not supported in remote storage.
func (rs *RemoteStorage) CreatePermission(_ context.Context, _ *models.Permission) (*models.Permission, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

// AssignPermissionToRole is not supported in remote storage.
func (rs *RemoteStorage) AssignPermissionToRole(_ context.Context, _, _ uint) error {
	return fmt.Errorf("not supported in remote storage")
}

// --- Namespace / Zone / Environment (not supported in remote mode) ---

func (rs *RemoteStorage) CreateNamespace(_ context.Context, _ *models.Namespace) (*models.Namespace, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateZone(_ context.Context, _ *models.Zone) (*models.Zone, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) CreateEnvironment(_ context.Context, _ *models.Environment) (*models.Environment, error) {
	return nil, fmt.Errorf("not supported in remote storage")
}

func (rs *RemoteStorage) ListNamespaces(_ context.Context) ([]*models.Namespace, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}

func (rs *RemoteStorage) ListZones(_ context.Context) ([]*models.Zone, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}

func (rs *RemoteStorage) ListEnvironments(_ context.Context) ([]*models.Environment, error) {
	return nil, fmt.Errorf("not implemented in remote storage")
}
