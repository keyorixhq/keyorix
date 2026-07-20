// local_version_comments.go — SecretVersionComment persistence (local SQLite/Postgres).
//
// Stores free-text annotations on specific secret versions, providing a
// human-readable audit trail of why a version was created or changed.
// For the remote stub equivalent see remote_version_comments.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSecretVersionComment(ctx context.Context, c *models.SecretVersionComment) error {
	return ls.db.WithContext(ctx).Create(c).Error
}

func (ls *LocalStorage) ListSecretVersionComments(ctx context.Context, versionID uint) ([]models.SecretVersionComment, error) {
	var comments []models.SecretVersionComment
	err := ls.db.WithContext(ctx).Where("version_id = ?", versionID).Order("created_at asc").Find(&comments).Error
	return comments, err
}

func (ls *LocalStorage) DeleteSecretVersionComment(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.SecretVersionComment{}, id).Error
}
