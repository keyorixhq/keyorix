// local_rbac.go — Role and RBAC operations for LocalStorage.
//
// Covers: CreatePermission, AssignPermissionToRole,
//
//	CreateRole, GetRole, GetRoleByName, UpdateRole, DeleteRole, ListRoles,
//	AssignRole, RemoveRole, GetUserRoles, CheckPermission, GetUserPermissions.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_rbac.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Permissions ---

func (ls *LocalStorage) CreatePermission(ctx context.Context, permission *models.Permission) (*models.Permission, error) {
	if err := ls.db.WithContext(ctx).Create(permission).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return permission, nil
}

func (ls *LocalStorage) AssignPermissionToRole(ctx context.Context, roleID, permissionID uint) error {
	rp := models.RolePermission{RoleID: roleID, PermissionID: permissionID}
	if err := ls.db.WithContext(ctx).Create(&rp).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// --- Roles ---

func (ls *LocalStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

func (ls *LocalStorage) GetRole(ctx context.Context, id uint) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).First(&role, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

func (ls *LocalStorage) GetRoleByName(ctx context.Context, name string) (*models.Role, error) {
	var role models.Role
	if err := ls.db.WithContext(ctx).Where("name = ?", name).First(&role).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &role, nil
}

func (ls *LocalStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Save(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

func (ls *LocalStorage) DeleteRole(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Role{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	if err := ls.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// --- RBAC assignment ---

// AssignRole assigns a role to a user; returns an error if already assigned.
func (ls *LocalStorage) AssignRole(ctx context.Context, userID, roleID uint) error {
	var existing models.UserRole
	err := ls.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	userRole := models.UserRole{UserID: userID, RoleID: roleID}
	if err := ls.db.WithContext(ctx).Create(&userRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRole removes a role from a user.
func (ls *LocalStorage) RemoveRole(ctx context.Context, userID, roleID uint) error {
	result := ls.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).Delete(&models.UserRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
}

// GetUserRoles retrieves all roles assigned to userID via the user_roles join table.
func (ls *LocalStorage) GetUserRoles(ctx context.Context, userID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN user_roles ON roles.id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// CheckPermission returns true if userID has the given resource/action permission.
// Resolved transitively: user → role → permission.
func (ls *LocalStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	var count int64
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ? AND permissions.resource = ? AND permissions.action = ?", userID, resource, action).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return count > 0, nil
}

// GetUserPermissions retrieves all distinct permissions for userID via role membership.
func (ls *LocalStorage) GetUserPermissions(ctx context.Context, userID uint) ([]*storage.Permission, error) {
	var permissions []*storage.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Select("permissions.id, permissions.name, permissions.description, permissions.resource, permissions.action").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Joins("JOIN user_roles ON role_permissions.role_id = user_roles.role_id").
		Where("user_roles.user_id = ?", userID).
		Group("permissions.id").
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}
