// local_version_comments.go — SecretVersionComment persistence (local SQLite/Postgres).
//
// Stores free-text annotations on specific secret versions, providing a
// human-readable audit trail of why a version was created or changed.
// For the remote stub equivalent see remote_version_comments.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error {
	return ls.db.WithContext(ctx).Create(c).Error
}

// ListSecretVersionComments returns comments for versionID, scoped to secretID
// so a caller authorized on one secret cannot walk the globally-shared
// VersionID space to read another tenant's comments (#G53).
func (ls *LocalStorage) ListSecretVersionComments(ctx context.Context, secretID, versionID uint) ([]models.SecretVersionComment, error) {
	var comments []models.SecretVersionComment
	err := ls.db.WithContext(ctx).
		Where("secret_id = ? AND version_id = ?", secretID, versionID).
		Order("created_at asc").Find(&comments).Error
	return comments, err
}

// DeleteSecretVersionComment removes the comment with the given ID, but only
// if it actually belongs to secretID/versionID — cross-checking the
// sub-resource IDs against their claimed parent instead of trusting id alone
// (#G53). RowsAffected==0 means either the comment doesn't exist or it
// belongs to a different secret/version; both are reported as not-found.
func (ls *LocalStorage) DeleteSecretVersionComment(ctx context.Context, secretID, versionID, id uint) error {
	result := ls.db.WithContext(ctx).
		Where("id = ? AND secret_id = ? AND version_id = ?", id, secretID, versionID).
		Delete(&models.SecretVersionComment{})
	if result.Error != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return nil
}
