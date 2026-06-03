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

// AssignRole assigns a role to a user at scope; errors if already assigned there.
func (ls *LocalStorage) AssignRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	var existing models.UserRole
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			userID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	userRole := models.UserRole{
		UserID:        userID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
	}
	if err := ls.db.WithContext(ctx).Create(&userRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRole removes a role from a user at scope.
func (ls *LocalStorage) RemoveRole(ctx context.Context, userID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("user_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			userID, roleID, scope.ProjectID, scope.EnvironmentID).Delete(&models.UserRole{})
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

// GetUserRoleIDsAt returns the IDs of roles directly assigned to userID that
// apply at the target scope: a stored assignment applies when its project is
// global (0) or equal, and its environment is global (0) or equal.
func (ls *LocalStorage) GetUserRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ?", userID).
		Where("project_id = 0 OR project_id = ?", scope.ProjectID).
		Where("environment_id = 0 OR environment_id = ?", scope.EnvironmentID).
		Distinct().Pluck("role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetUserRoleIDsExact returns the IDs of roles directly assigned to userID at
// exactly the given scope (no global/inherited matching). Used for full
// replacement of a user's roles at one scope.
func (ls *LocalStorage) GetUserRoleIDsExact(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Model(&models.UserRole{}).
		Where("user_id = ? AND project_id = ? AND environment_id = ?",
			userID, scope.ProjectID, scope.EnvironmentID).
		Distinct().Pluck("role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// GetUserGroupRoleIDsAt returns the IDs of roles userID inherits via group
// membership that apply at the target scope (same scope-matching rule as
// GetUserRoleIDsAt).
func (ls *LocalStorage) GetUserGroupRoleIDsAt(ctx context.Context, userID uint, scope storage.Scope) ([]uint, error) {
	var ids []uint
	err := ls.db.WithContext(ctx).Table("group_roles").
		Joins("JOIN user_groups ON user_groups.group_id = group_roles.group_id").
		Where("user_groups.user_id = ?", userID).
		Where("group_roles.project_id = 0 OR group_roles.project_id = ?", scope.ProjectID).
		Where("group_roles.environment_id = 0 OR group_roles.environment_id = ?", scope.EnvironmentID).
		Distinct().Pluck("group_roles.role_id", &ids).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return ids, nil
}

// RoleSetHasPermission reports whether any role in roleIDs grants the named
// permission (e.g. "secrets.read") via the role_permissions join.
func (ls *LocalStorage) RoleSetHasPermission(ctx context.Context, roleIDs []uint, permission string) (bool, error) {
	if len(roleIDs) == 0 {
		return false, nil
	}
	var count int64
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id IN ?", roleIDs).
		Where("permissions.name = ?", permission).
		Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	return count > 0, nil
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

// ListPermissions returns all permissions.
func (ls *LocalStorage) ListPermissions(ctx context.Context) ([]*models.Permission, error) {
	var permissions []*models.Permission
	if err := ls.db.WithContext(ctx).Find(&permissions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// GetPermission returns a single permission by ID.
func (ls *LocalStorage) GetPermission(ctx context.Context, id uint) (*models.Permission, error) {
	var permission models.Permission
	if err := ls.db.WithContext(ctx).First(&permission, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &permission, nil
}

// GetRolePermissions returns all permissions assigned to a role.
func (ls *LocalStorage) GetRolePermissions(ctx context.Context, roleID uint) ([]*models.Permission, error) {
	var permissions []*models.Permission
	err := ls.db.WithContext(ctx).Table("permissions").
		Joins("JOIN role_permissions ON permissions.id = role_permissions.permission_id").
		Where("role_permissions.role_id = ?", roleID).
		Find(&permissions).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return permissions, nil
}

// RemovePermissionFromRole removes a permission from a role.
func (ls *LocalStorage) RemovePermissionFromRole(ctx context.Context, roleID, permissionID uint) error {
	result := ls.db.WithContext(ctx).
		Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

// GetGroupRoles returns all roles assigned to a group.
func (ls *LocalStorage) GetGroupRoles(ctx context.Context, groupID uint) ([]*models.Role, error) {
	var roles []*models.Role
	err := ls.db.WithContext(ctx).Table("roles").
		Joins("JOIN group_roles ON roles.id = group_roles.role_id").
		Where("group_roles.group_id = ?", groupID).
		Find(&roles).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// AssignRoleToGroup assigns a role to a group at scope; errors if already assigned there.
func (ls *LocalStorage) AssignRoleToGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	var existing models.GroupRole
	err := ls.db.WithContext(ctx).
		Where("group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	groupRole := models.GroupRole{
		GroupID:       groupID,
		RoleID:        roleID,
		ProjectID:     scope.ProjectID,
		EnvironmentID: scope.EnvironmentID,
	}
	if err := ls.db.WithContext(ctx).Create(&groupRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveRoleFromGroup removes a role from a group at scope.
func (ls *LocalStorage) RemoveRoleFromGroup(ctx context.Context, groupID, roleID uint, scope storage.Scope) error {
	result := ls.db.WithContext(ctx).
		Where("group_id = ? AND role_id = ? AND project_id = ? AND environment_id = ?",
			groupID, roleID, scope.ProjectID, scope.EnvironmentID).
		Delete(&models.GroupRole{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorRoleNotAssigned", nil))
	}
	return nil
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
