package core

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// AssignRoleToUser assigns a role to a user by email and role name.
func (c *KeyorixCore) AssignRoleToUser(ctx context.Context, userEmail, roleName string) error {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.AssignRole(ctx, user.ID, role.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRoleFromUser removes a role from a user by email and role name.
func (c *KeyorixCore) RemoveRoleFromUser(ctx context.Context, userEmail, roleName string) error {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	role, err := c.storage.GetRoleByName(ctx, roleName)
	if err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorRoleNotFound", nil), err)
	}
	if err := c.storage.RemoveRole(ctx, user.ID, role.ID); err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ListUserRolesByEmail lists roles for a user by email.
func (c *KeyorixCore) ListUserRolesByEmail(ctx context.Context, userEmail string) ([]*models.Role, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	roles, err := c.storage.GetUserRoles(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// HasPermissionByEmail checks if a user has a specific permission by email.
func (c *KeyorixCore) HasPermissionByEmail(ctx context.Context, userEmail, resource, action string) (bool, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	hasPermission, err := c.storage.CheckPermission(ctx, user.ID, resource, action)
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return hasPermission, nil
}

// ListUserPermissionsByEmail lists permissions for a user by email.
func (c *KeyorixCore) ListUserPermissionsByEmail(ctx context.Context, userEmail string) ([]*storage.Permission, error) {
	user, err := c.storage.GetUserByEmail(ctx, userEmail)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorUserNotFound", nil), err)
	}
	permissions, err := c.storage.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}
