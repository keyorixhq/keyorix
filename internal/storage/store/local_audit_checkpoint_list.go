// local_audit_checkpoint_list.go — read every signed checkpoint row, not only
// the latest (accept-loss checks each signed head against the current rows,
// #3802). Read-only: the rows are never changed here.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListAuditCheckpoints returns up to limit checkpoints with an id above
// afterID, oldest first.
func (ls *LocalStorage) ListAuditCheckpoints(ctx context.Context, afterID uint, limit int) ([]*models.AuditCheckpoint, error) {
	var out []*models.AuditCheckpoint
	if limit <= 0 {
		return out, nil
	}
	err := ls.db.WithContext(ctx).Where("id > ?", afterID).Order("id ASC").Limit(limit).Find(&out).Error
	return out, err
}
