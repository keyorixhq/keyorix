package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RoleWithPermissions embeds a Role and includes its assigned permissions.
type RoleWithPermissions struct {
	models.Role
	Permissions []*models.Permission `json:"permissions"`
}

// UserRoleAssignment holds a user's identity alongside their assigned roles.
type UserRoleAssignment struct {
	UserID   uint           `json:"user_id"`
	Username string         `json:"username"`
	Email    string         `json:"email"`
	Roles    []*models.Role `json:"roles"`
}

// ListPermissions returns all permissions.
func (c *KeyorixCore) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	permissions, err := c.storage.ListPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetRoleWithPermissions returns a role and its assigned permissions.
func (c *KeyorixCore) GetRoleWithPermissions(ctx context.Context, roleID uint) (*models.Role, []*models.Permission, error) {
	role, err := c.storage.GetRole(ctx, roleID)
	if err != nil {
		return nil, nil, err
	}
	perms, err := c.storage.GetRolePermissions(ctx, roleID)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return role, perms, nil
}

// AssignPermissionToRole verifies both exist and assigns the permission.
func (c *KeyorixCore) AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if _, err := c.storage.GetPermission(ctx, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	if err := c.storage.AssignPermissionToRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemovePermissionFromRole verifies the role exists then removes the permission.
func (c *KeyorixCore) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error {
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.RemovePermissionFromRole(ctx, roleID, permissionID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// GetGroupRoles returns all roles assigned to a group.
func (c *KeyorixCore) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetGroupRoles(ctx, groupID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// AssignRoleToGroup verifies both exist then assigns the role at scope.
func (c *KeyorixCore) AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope Scope) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if _, err := c.storage.GetRole(ctx, roleID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.AssignRoleToGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRoleFromGroup verifies the group exists then removes the role at scope.
func (c *KeyorixCore) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope Scope) error {
	if _, err := c.storage.GetGroup(ctx, groupID); err != nil {
		return fmt.Errorf("group not found: %w", err)
	}
	if err := c.storage.RemoveRoleFromGroup(ctx, groupID, roleID, scope); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListRolesWithPermissions returns all roles with their permission sets.
func (c *KeyorixCore) ListRolesWithPermissions(ctx context.Context) ([]*RoleWithPermissions, error) {
	roles, err := c.storage.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	result := make([]*RoleWithPermissions, 0, len(roles))
	for _, role := range roles {
		perms, err := c.storage.GetRolePermissions(ctx, role.ID)
		if err != nil {
			perms = []*models.Permission{}
		}
		result = append(result, &RoleWithPermissions{
			Role:        *role,
			Permissions: perms,
		})
	}
	return result, nil
}

// GetUserRoleAssignment returns a user's identity and assigned roles.
func (c *KeyorixCore) GetUserRoleAssignment(ctx context.Context, userID uint) (*UserRoleAssignment, error) {
	user, err := c.storage.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &UserRoleAssignment{
		UserID:   user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    roles,
	}, nil
}

// GetUserRolesByID returns the roles assigned to the given user ID.
func (c *KeyorixCore) GetUserRolesByID(ctx context.Context, userID uint) ([]*models.Role, error) {
	roles, err := c.storage.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// SetUserRoles does a full replacement of the roles assigned to a user at the
// given scope. Only assignments at exactly that scope are considered: roles
// present there but not in roleIDs are removed; roles in roleIDs not already
// assigned there are added. Assignments at other scopes are left untouched.
func (c *KeyorixCore) SetUserRoles(ctx context.Context, userID uint, roleIDs []uint, scope Scope) error {
	current, err := c.storage.GetUserRoleIDsExact(ctx, userID, scope)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	currentSet := make(map[uint]bool, len(current))
	for _, id := range current {
		currentSet[id] = true
	}
	newSet := make(map[uint]bool, len(roleIDs))
	for _, id := range roleIDs {
		newSet[id] = true
	}
	for _, id := range current {
		if !newSet[id] {
			if err := c.storage.RemoveRole(ctx, userID, id, scope); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
		}
	}
	for _, id := range roleIDs {
		if !currentSet[id] {
			if err := c.storage.AssignRole(ctx, userID, id, scope); err != nil {
				return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
			}
		}
	}
	return nil
}
