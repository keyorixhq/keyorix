// local_purge.go — retention purge of soft-deleted rows (ADR-032).
//
// Each method hard-deletes (Unscoped) rows whose deleted_at predates the cutoff,
// returning the count removed. The purge scheduler (main.go) drives these on an
// interval when enabled. Irreversible by design — the retention window is the
// only safety net.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) purgeDeletedBefore(ctx context.Context, model interface{}, before time.Time) (int64, error) {
	result := ls.db.WithContext(ctx).Unscoped().
		Where("deleted_at IS NOT NULL AND deleted_at < ?", before).
		Delete(model)
	if result.Error != nil {
		return 0, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	return result.RowsAffected, nil
}

func (ls *LocalStorage) PurgeDeletedUsersBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.User{}, before)
}

func (ls *LocalStorage) PurgeDeletedProjectsBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.Project{}, before)
}

func (ls *LocalStorage) PurgeDeletedEnvironmentsBefore(ctx context.Context, before time.Time) (int64, error) {
	return ls.purgeDeletedBefore(ctx, &models.Environment{}, before)
}
