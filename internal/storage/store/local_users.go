// local_users.go — User and Group operations for LocalStorage.
//
// Covers: CreateUser, GetUser, GetUserByEmail, GetUserByUsername, UpdateUser,
//
//	DeleteUser, RestoreUser, ListUsers, GetUserGroups,
//	CreateGroup, GetGroup, UpdateGroup, DeleteGroup, ListGroups,
//	AddUserToGroup, RemoveUserFromGroup, ListGroupMembers.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_users.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// --- Users ---

func (ls *LocalStorage) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

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

func (ls *LocalStorage) UpdateUser(ctx context.Context, user *models.User) (*models.User, error) {
	if err := ls.db.WithContext(ctx).Save(user).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return user, nil
}

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

func (ls *LocalStorage) RestoreUser(ctx context.Context, id uint) error {
	// Use Unscoped to find and update the soft-deleted row.
	result := ls.db.WithContext(ctx).Unscoped().Model(&models.User{}).Where("id = ? AND deleted_at IS NOT NULL", id).Update("deleted_at", nil)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
	}
	return nil
}

func (ls *LocalStorage) ListUsers(ctx context.Context, filter *storage.UserFilter) ([]*models.User, int64, error) {
	query := ls.db.WithContext(ctx).Model(&models.User{})

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

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}

	offset := (filter.Page - 1) * filter.PageSize
	query = query.Offset(offset).Limit(filter.PageSize)

	var users []*models.User
	if err := query.Find(&users).Error; err != nil {
		return nil, 0, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return users, total, nil
}

// GetUserGroups retrieves all groups a user is a member of.
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

// --- Groups ---

func (ls *LocalStorage) CreateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Create(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

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

func (ls *LocalStorage) UpdateGroup(ctx context.Context, group *models.Group) (*models.Group, error) {
	if err := ls.db.WithContext(ctx).Save(group).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return group, nil
}

// DeleteGroup cascades: removes GroupRole and UserGroup join rows before deleting the group.
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

func (ls *LocalStorage) ListGroups(ctx context.Context) ([]*models.Group, error) {
	var groups []*models.Group
	if err := ls.db.WithContext(ctx).Order("name").Find(&groups).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return groups, nil
}

// AddUserToGroup adds userID to groupID; idempotent (existing membership is a no-op).
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
		return nil // already a member
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

func (ls *LocalStorage) RemoveUserFromGroup(ctx context.Context, userID, groupID uint) error {
	result := ls.db.WithContext(ctx).Where("user_id = ? AND group_id = ?", userID, groupID).Delete(&models.UserGroup{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

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
