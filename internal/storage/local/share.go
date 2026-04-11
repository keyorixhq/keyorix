package local

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// CreateShareRecord creates a new share record
func (s *LocalStorage) CreateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	// Validate the share record
	if err := models.ValidateShareRecord(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}

	// Check if the secret exists
	secret, err := s.GetSecret(ctx, share.SecretID)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorSecretNotFound", nil), err)
	}

	// Check if the owner is the actual owner of the secret
	if secret.OwnerID != share.OwnerID {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
	}

	// Check if the recipient exists
	if share.IsGroup {
		// Check if group exists
		var count int64
		if err := s.db.Model(&models.Group{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorGroupNotFound", nil))
		}
	} else {
		// Check if user exists
		var count int64
		if err := s.db.Model(&models.User{}).Where("id = ?", share.RecipientID).Count(&count).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		if count == 0 {
			return nil, fmt.Errorf("%s", i18n.T("ErrorUserNotFound", nil))
		}
	}

	// Check if share already exists
	var existingShare models.ShareRecord
	result := s.db.Where("secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 
		share.SecretID, share.RecipientID, share.IsGroup).First(&existingShare)
	
	if result.Error == nil {
		// Share already exists, update it
		existingShare.Permission = share.Permission
		existingShare.UpdatedAt = time.Now()
		
		if err := s.db.Save(&existingShare).Error; err != nil {
			return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
		}
		
		return &existingShare, nil
	} else if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
		// Some other error occurred
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), result.Error)
	}

	// Create new share record
	if err := s.db.Create(share).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}

	return share, nil
}

// GetShareRecord retrieves a share record by ID
func (s *LocalStorage) GetShareRecord(ctx context.Context, shareID uint) (*models.ShareRecord, error) {
	var share models.ShareRecord
	
	if err := s.db.First(&share, shareID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("%s", i18n.T("ErrorShareNotFound", nil))
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return &share, nil
}

// UpdateShareRecord updates an existing share record
func (s *LocalStorage) UpdateShareRecord(ctx context.Context, share *models.ShareRecord) (*models.ShareRecord, error) {
	// Validate the share update
	if err := models.ValidateShareUpdate(share); err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorValidation", nil), err)
	}
	
	// Check if the share exists
	existingShare, err := s.GetShareRecord(ctx, share.ID)
	if err != nil {
		return nil, err
	}
	
	// Update only allowed fields
	existingShare.Permission = share.Permission
	existingShare.UpdatedAt = time.Now()
	
	if err := s.db.Save(existingShare).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return existingShare, nil
}

// DeleteShareRecord deletes a share record (soft delete)
func (s *LocalStorage) DeleteShareRecord(ctx context.Context, shareID uint) error {
	// Check if the share exists
	share, err := s.GetShareRecord(ctx, shareID)
	if err != nil {
		return err
	}
	
	// Soft delete the share record
	if err := s.db.Delete(share).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return nil
}

// ListSharesBySecret lists all share records for a secret
func (s *LocalStorage) ListSharesBySecret(ctx context.Context, secretID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	
	if err := s.db.Where("secret_id = ? AND deleted_at IS NULL", secretID).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return shares, nil
}

// ListSharesByUser lists all share records where the user is the recipient
func (s *LocalStorage) ListSharesByUser(ctx context.Context, userID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	
	if err := s.db.Where("recipient_id = ? AND is_group = ? AND deleted_at IS NULL", userID, false).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return shares, nil
}

// ListSharesByOwner lists all share records created by secrets owned by this user (share owner_id)
func (s *LocalStorage) ListSharesByOwner(ctx context.Context, ownerID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	if err := s.db.Where("owner_id = ? AND deleted_at IS NULL", ownerID).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	return shares, nil
}

// ListSharesByGroup lists all share records where the group is the recipient
func (s *LocalStorage) ListSharesByGroup(ctx context.Context, groupID uint) ([]*models.ShareRecord, error) {
	var shares []*models.ShareRecord
	
	if err := s.db.Where("recipient_id = ? AND is_group = ? AND deleted_at IS NULL", groupID, true).Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	return shares, nil
}

// ListSharedSecrets lists all secrets shared with a user
func (s *LocalStorage) ListSharedSecrets(ctx context.Context, userID uint) ([]*models.SecretNode, error) {
	var secrets []*models.SecretNode
	
	// Get secrets shared directly with the user
	query := `
		SELECT s.* FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		WHERE sr.recipient_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
	`
	if err := s.db.Raw(query, userID, false).Scan(&secrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	// Get secrets shared with groups the user belongs to
	groupQuery := `
		SELECT s.* FROM secret_nodes s
		JOIN share_records sr ON s.id = sr.secret_id
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		WHERE ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
	`
	var groupSharedSecrets []*models.SecretNode
	if err := s.db.Raw(groupQuery, userID, true).Scan(&groupSharedSecrets).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	// Combine both sets of secrets
	secrets = append(secrets, groupSharedSecrets...)
	
	return secrets, nil
}

// CheckSharePermission checks if a user has permission to access a secret
func (s *LocalStorage) CheckSharePermission(ctx context.Context, secretID, userID uint) (string, error) {
	// Check if user is the owner
	var secret models.SecretNode
	if err := s.db.First(&secret, secretID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", fmt.Errorf("%s", i18n.T("ErrorSecretNotFound", nil))
		}
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), err)
	}
	
	// If user is the owner, they have write permission
	if secret.OwnerID == userID {
		return "write", nil
	}
	
	// Check direct shares
	var directShare models.ShareRecord
	directResult := s.db.Where(
		"secret_id = ? AND recipient_id = ? AND is_group = ? AND deleted_at IS NULL", 
		secretID, userID, false,
	).First(&directShare)
	
	if directResult.Error == nil {
		return directShare.Permission, nil
	} else if !errors.Is(directResult.Error, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), directResult.Error)
	}
	
	// Check group shares
	var groupShare models.ShareRecord
	groupQuery := `
		SELECT sr.* FROM share_records sr
		JOIN user_groups ug ON sr.recipient_id = ug.group_id
		WHERE sr.secret_id = ? AND ug.user_id = ? AND sr.is_group = ? AND sr.deleted_at IS NULL
		LIMIT 1
	`
	groupResult := s.db.Raw(groupQuery, secretID, userID, true).Scan(&groupShare)
	
	if groupResult.Error == nil && groupShare.ID != 0 {
		return groupShare.Permission, nil
	} else if groupResult.Error != nil && !errors.Is(groupResult.Error, gorm.ErrRecordNotFound) {
		return "", fmt.Errorf("%s: %w", i18n.T("ErrorDatabaseOperation", nil), groupResult.Error)
	}
	
	// No permission found
	return "", fmt.Errorf("%s", i18n.T("ErrorNotAuthorized", nil))
}