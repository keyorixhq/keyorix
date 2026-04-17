package local

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// LocalStorage implements the Storage interface using direct database access
// This is used when the CLI or server runs on the same host as the database
type LocalStorage struct {
	db *gorm.DB
}

// NewLocalStorage creates a new LocalStorage instance
func NewLocalStorage(db *gorm.DB) *LocalStorage {
	return &LocalStorage{
		db: db,
	}
}

// Namespace / Environment lookup

func (ls *LocalStorage) ListNamespaces(ctx context.Context) ([]*models.Namespace, error) {
	var namespaces []*models.Namespace
	return namespaces, ls.db.WithContext(ctx).Find(&namespaces).Error
}

func (ls *LocalStorage) ListZones(ctx context.Context) ([]*models.Zone, error) {
	var zones []*models.Zone
	return zones, ls.db.WithContext(ctx).Find(&zones).Error
}

func (ls *LocalStorage) ListEnvironments(ctx context.Context) ([]*models.Environment, error) {
	var environments []*models.Environment
	return environments, ls.db.WithContext(ctx).Find(&environments).Error
}

// Secret Management Implementation

// CreateSecret creates a new secret in the database
func (ls *LocalStorage) CreateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Create(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// GetSecret retrieves a secret by ID
func (ls *LocalStorage) GetSecret(ctx context.Context, id uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	if err := ls.db.WithContext(ctx).First(&secret, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// GetSecretByName retrieves a secret by name and scope
func (ls *LocalStorage) GetSecretByName(ctx context.Context, name string, namespaceID, zoneID, environmentID uint) (*models.SecretNode, error) {
	var secret models.SecretNode
	err := ls.db.WithContext(ctx).Where(
		"name = ? AND namespace_id = ? AND zone_id = ? AND environment_id = ?",
		name, namespaceID, zoneID, environmentID,
	).First(&secret).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &secret, nil
}

// UpdateSecret updates an existing secret
func (ls *LocalStorage) UpdateSecret(ctx context.Context, secret *models.SecretNode) (*models.SecretNode, error) {
	if err := ls.db.WithContext(ctx).Save(secret).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return secret, nil
}

// DeleteSecret deletes a secret by ID
func (ls *LocalStorage) DeleteSecret(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretNode{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
	}
	return nil
}

// ListSecrets lists secrets with filtering and pagination
func (ls *LocalStorage) ListSecrets(ctx context.Context, filter *storage.SecretFilter) ([]*models.SecretNode, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.SecretNode{})

	// Apply filters
	if filter.NamespaceID != nil {
		query = query.Where("namespace_id = ?", *filter.NamespaceID)
	}
	if filter.ZoneID != nil {
		query = query.Where("zone_id = ?", *filter.ZoneID)
	}
	if filter.EnvironmentID != nil {
		query = query.Where("environment_id = ?", *filter.EnvironmentID)
	}
	if filter.Type != nil {
		query = query.Where("type = ?", *filter.Type)
	}
	if filter.CreatedBy != nil {
		query = query.Where("created_by = ?", *filter.CreatedBy)
	}
	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", *filter.CreatedAfter)
	}
	if filter.CreatedBefore != nil {
		query = query.Where("created_at < ?", *filter.CreatedBefore)
	}

	// Count total records
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Apply pagination
	offset := (filter.Page - 1) * filter.PageSize
	query = query.Offset(offset).Limit(filter.PageSize)

	// Execute query
	var secrets []*models.SecretNode
	if err := query.Find(&secrets).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	return secrets, total, nil
}

// GetSecretVersions retrieves all versions of a secret
func (ls *LocalStorage) GetSecretVersions(ctx context.Context, secretID uint) ([]*models.SecretVersion, error) {
	var versions []*models.SecretVersion
	if err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretID).Order("version_number DESC").Find(&versions).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return versions, nil
}

// CreateSecretVersion creates a new version of a secret
func (ls *LocalStorage) CreateSecretVersion(ctx context.Context, version *models.SecretVersion) (*models.SecretVersion, error) {
	if err := ls.db.WithContext(ctx).Create(version).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return version, nil
}

// GetLatestSecretVersion retrieves the latest version of a secret
func (ls *LocalStorage) GetLatestSecretVersion(ctx context.Context, secretID uint) (*models.SecretVersion, error) {
	var version models.SecretVersion
	if err := ls.db.WithContext(ctx).Where("secret_node_id = ?", secretID).Order("version_number DESC").First(&version).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorVersionNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &version, nil
}

// IncrementSecretReadCount increments the read count for a secret version
func (ls *LocalStorage) IncrementSecretReadCount(ctx context.Context, versionID uint) error {
	if err := ls.db.WithContext(ctx).Model(&models.SecretVersion{}).Where("id = ?", versionID).UpdateColumn("read_count", gorm.Expr("read_count + 1")).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// User Management Implementation

// CreateUser creates a new user in the database
func (ls *LocalStorage) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

// GetUser retrieves a user by ID
func (ls *LocalStorage) GetUser(ctx context.Context, id uint) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).First(&user, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

// GetUserByEmail retrieves a user by email
func (ls *LocalStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).Where("email = ?", email).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

// UpdateUser updates an existing user
func (ls *LocalStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Save(user).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

// DeleteUser deletes a user by ID
func (ls *LocalStorage) DeleteUser(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.User{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

// ListUsers lists users with filtering and pagination
func (ls *LocalStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.User{})

	// Apply filters
	if filter.Search != nil {
		pattern := "%" + *filter.Search + "%"
		query = query.Where("username LIKE ? OR email LIKE ?", pattern, pattern)
	}
	if filter.Username != nil {
		query = query.Where("username LIKE ?", "%"+*filter.Username+"%")
	}
	if filter.Email != nil {
		query = query.Where("email LIKE ?", "%"+*filter.Email+"%")
	}
	if filter.IsActive != nil {
		query = query.Where("is_active = ?", *filter.IsActive)
	}
	if filter.CreatedAfter != nil {
		query = query.Where("created_at > ?", *filter.CreatedAfter)
	}

	// Count total records
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	// Apply pagination
	offset := (filter.Page - 1) * filter.PageSize
	query = query.Offset(offset).Limit(filter.PageSize)

	// Execute query
	var users []*models.User
	if err := query.Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	return users, total, nil
}

// GetUserByUsername retrieves a user by username
func (ls *LocalStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	var user models.User
	if err := ls.db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &user, nil
}

// CreateGroup creates a new group
func (ls *LocalStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

// GetGroup retrieves a group by ID
func (ls *LocalStorage) GetGroup(ctx context.Context, id uint) (*models.Group, error) {
	var group models.Group
	if err := ls.db.WithContext(ctx).First(&group, id).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &group, nil
}

// UpdateGroup updates an existing group
func (ls *LocalStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Save(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

// DeleteGroup deletes a group by ID
func (ls *LocalStorage) DeleteGroup(ctx context.Context, id uint) error {
	if _, err := ls.GetGroup(ctx, id); err != nil {
		return err
	}
	if err := ls.db.WithContext(ctx).Where("group_id = ?", id).Delete(&models.GroupRole{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	if err := ls.db.WithContext(ctx).Where("group_id = ?", id).Delete(&models.UserGroup{}).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	result := ls.db.WithContext(ctx).Delete(&models.Group{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
	}
	return nil
}

// ListGroups lists all groups
func (ls *LocalStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	var groups []*models.Group
	if err := ls.db.WithContext(ctx).Order("name").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// AddUserToGroup adds a user to a group
func (ls *LocalStorage) AddUserToGroup(ctx context.Context, userID, groupID uint) error {
	if _, err := ls.GetUser(ctx, userID); err != nil {
		return err
	}
	if _, err := ls.GetGroup(ctx, groupID); err != nil {
		return err
	}
	var existing models.UserGroup
	err := ls.db.WithContext(ctx).Where("user_id = ? AND group_id = ?", userID, groupID).First(&existing).Error
	if err == nil {
		return nil
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}
	ug := models.UserGroup{UserID: userID, GroupID: groupID}
	if err := ls.db.WithContext(ctx).Create(&ug).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a group
func (ls *LocalStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	result := ls.db.WithContext(ctx).Where("user_id = ? AND group_id = ?", userID, groupID).Delete(&models.UserGroup{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// ListGroupMembers lists all users in a group
func (ls *LocalStorage) ListGroupMembers(ctx context.Context, groupID uint) ([]*models.User, error) {
	if _, err := ls.GetGroup(ctx, groupID); err != nil {
		return nil, err
	}
	var users []*models.User
	err := ls.db.WithContext(ctx).Model(&models.User{}).
		Joins("JOIN user_groups ON user_groups.user_id = users.id").
		Where("user_groups.group_id = ?", groupID).
		Find(&users).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, nil
}

// Role Management Implementation

// CreateRole creates a new role in the database
func (ls *LocalStorage) CreateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Create(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

// GetRole retrieves a role by ID
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

// GetRoleByName retrieves a role by name
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

// UpdateRole updates an existing role
func (ls *LocalStorage) UpdateRole(ctx context.Context, role *models.Role) (*models.Role, error) {
	if err := ls.db.WithContext(ctx).Save(role).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return role, nil
}

// DeleteRole deletes a role by ID
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

// ListRoles lists all roles
func (ls *LocalStorage) ListRoles(ctx context.Context) ([]*models.Role, error) {
	var roles []*models.Role
	if err := ls.db.WithContext(ctx).Find(&roles).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return roles, nil
}

// RBAC Operations Implementation

// AssignRole assigns a role to a user
func (ls *LocalStorage) AssignRole(ctx context.Context, userID, roleID uint) error {
	// Check if assignment already exists
	var existing models.UserRole
	err := ls.db.WithContext(ctx).Where("user_id = ? AND role_id = ?", userID, roleID).First(&existing).Error
	if err == nil {
		return fmt.Errorf("%s", i18n.T("ErrorRoleAlreadyAssigned", nil))
	}
	if err != gorm.ErrRecordNotFound {
		return fmt.Errorf("%s: %w", i18n.T("ErrorInternalServer", nil), err)
	}

	// Create new assignment
	userRole := models.UserRole{
		UserID: userID,
		RoleID: roleID,
	}
	if err := ls.db.WithContext(ctx).Create(&userRole).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}

	return nil
}

// RemoveRole removes a role from a user
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

// GetUserRoles retrieves all roles assigned to a user
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

// CheckPermission checks if a user has a specific permission
func (ls *LocalStorage) CheckPermission(ctx context.Context, userID uint, resource, action string) (bool, error) {
	// This is a simplified implementation
	// In a real system, you'd check against a permissions table
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

// GetUserPermissions retrieves all permissions for a user
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

// Placeholder implementations for remaining methods
// These would be implemented based on your specific requirements

func (ls *LocalStorage) LogAuditEvent(ctx context.Context, event *models.AuditEvent) error {
	return ls.db.WithContext(ctx).Create(event).Error
}

func (ls *LocalStorage) CreateSecretAccessLog(ctx context.Context, log *models.SecretAccessLog) error {
	return ls.db.WithContext(ctx).Create(log).Error
}

func (ls *LocalStorage) GetAuditLogs(ctx context.Context, filter *storage.AuditFilter) ([]*models.AuditEvent, int64, error) {
	// Implementation would depend on your audit event model
	return nil, 0, nil
}

func (ls *LocalStorage) GetRBACAuditLogs(ctx context.Context, filter *storage.RBACAuditFilter) ([]*storage.RBACAuditLog, int64, error) {
	// Implementation would depend on your RBAC audit model
	return nil, 0, nil
}

func (ls *LocalStorage) CreateSession(ctx context.Context, session *models.Session) (*models.Session, error) {
	if err := ls.db.WithContext(ctx).Create(session).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return session, nil
}

func (ls *LocalStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	var session models.Session
	if err := ls.db.WithContext(ctx).Where("session_token = ?", token).First(&session).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &session, nil
}

func (ls *LocalStorage) DeleteSession(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.Session{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

func (ls *LocalStorage) CleanupExpiredSessions(ctx context.Context) error {
	result := ls.db.WithContext(ctx).Where("expires_at < ?", time.Now()).Delete(&models.Session{})
	return result.Error
}

func (ls *LocalStorage) CreateAPIClient(ctx context.Context, client *models.APIClient) (*models.APIClient, error) {
	if err := ls.db.WithContext(ctx).Create(client).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return client, nil
}

func (ls *LocalStorage) GetAPIClient(ctx context.Context, clientID string) (*models.APIClient, error) {
	var client models.APIClient
	if err := ls.db.WithContext(ctx).Where("client_id = ?", clientID).First(&client).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return &client, nil
}

func (ls *LocalStorage) RevokeAPIClient(ctx context.Context, clientID string) error {
	result := ls.db.WithContext(ctx).Model(&models.APIClient{}).Where("client_id = ?", clientID).Update("is_active", false)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) HealthCheck(ctx context.Context) error {
	var result int
	return ls.db.WithContext(ctx).Raw("SELECT 1").Scan(&result).Error
}

// GetUserGroups retrieves all groups a user is a member of
func (ls *LocalStorage) GetUserGroups(ctx context.Context, userID uint) ([]*models.Group, error) {
	var groups []*models.Group
	err := ls.db.WithContext(ctx).Model(&models.Group{}).
		Joins("JOIN user_groups ON user_groups.group_id = groups.id").
		Where("user_groups.user_id = ?", userID).
		Find(&groups).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

func (ls *LocalStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	stats := &storage.StorageStats{}

	// Count secrets
	ls.db.WithContext(ctx).Model(&models.SecretNode{}).Count(&stats.TotalSecrets)

	// Count users
	ls.db.WithContext(ctx).Model(&models.User{}).Count(&stats.TotalUsers)

	// Count roles
	ls.db.WithContext(ctx).Model(&models.Role{}).Count(&stats.TotalRoles)

	// Count sessions
	ls.db.WithContext(ctx).Model(&models.Session{}).Count(&stats.TotalSessions)

	return stats, nil
}
