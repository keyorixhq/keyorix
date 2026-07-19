// local_secret_acl.go — SecretACL persistence (RBAC Phase 3).
// Each row grants a specific user access to one secret, independently of project RBAC.
// For the remote equivalent see remote_secret_acl.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm/clause"
)

// CreateOrUpdateSecretACL upserts a SecretACL row on the (secret_id, user_id) unique index.
func (ls *LocalStorage) CreateOrUpdateSecretACL(ctx context.Context, acl *models.SecretACL) error {
	result := ls.db.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "secret_id"}, {Name: "user_id"}},
			DoUpdates: clause.AssignmentColumns([]string{"permissions", "granted_by", "updated_at"}),
		}).
		Create(acl)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return nil
}

// ListSecretACLs returns all ACL grants for the given secret.
func (ls *LocalStorage) ListSecretACLs(ctx context.Context, secretID uint) ([]*models.SecretACL, error) {
	var rows []*models.SecretACL
	if err := ls.db.WithContext(ctx).Where("secret_id = ?", secretID).Order(sqlOrderIDAsc).Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// GetSecretACL returns the ACL for the given (secret, user) pair, or an error if not found.
func (ls *LocalStorage) GetSecretACL(ctx context.Context, secretID, userID uint) (*models.SecretACL, error) {
	var row models.SecretACL
	if err := ls.db.WithContext(ctx).Where("secret_id = ? AND user_id = ?", secretID, userID).First(&row).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &row, nil
}

// DeleteSecretACL deletes the ACL row with the given ID.
func (ls *LocalStorage) DeleteSecretACL(ctx context.Context, id uint) error {
	result := ls.db.WithContext(ctx).Delete(&models.SecretACL{}, id)
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}
