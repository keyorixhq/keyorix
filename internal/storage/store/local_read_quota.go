// local_read_quota.go — LocalStorage implementation of ListSecretsWithQuota,
// used by core.CheckReadQuotas to find secrets approaching their MaxReads cap.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsWithQuota returns every live secret (IsSecret=true, not
// soft-deleted) whose max_reads column is non-NULL and greater than zero.
func (ls *LocalStorage) ListSecretsWithQuota(ctx context.Context) ([]models.SecretNode, error) {
	var secrets []models.SecretNode
	return secrets, ls.db.WithContext(ctx).
		Where("is_secret = ? AND max_reads IS NOT NULL AND max_reads > 0 AND deleted_at IS NULL", true).
		Find(&secrets).Error
}
