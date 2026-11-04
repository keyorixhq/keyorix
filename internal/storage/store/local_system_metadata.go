// local_system_metadata.go — a small singleton key/value store for server-managed
// state (e.g. the audit-checkpoint high-water mark, ADR-029). Backed by the
// system_metadata table.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// GetSystemMetadata returns the value stored for key; found is false when the key
// has never been set.
func (ls *LocalStorage) GetSystemMetadata(ctx context.Context, key string) (string, bool, error) {
	var m models.SystemMetadata
	err := ls.db.WithContext(ctx).Where("key = ?", key).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return m.Value, true, nil
}

// SetSystemMetadata upserts a system-metadata key/value (last write wins).
func (ls *LocalStorage) SetSystemMetadata(ctx context.Context, key, value string) error {
	return ls.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "key"}},
		DoUpdates: clause.AssignmentColumns([]string{"value", "updated_at"}),
	}).Create(&models.SystemMetadata{Key: key, Value: value, UpdatedAt: time.Now().UTC()}).Error
}

// CompareAndSetSystemMetadata writes value for key only when the row still
// holds old (oldFound) or is still absent (!oldFound): a conditional UPDATE or
// an INSERT ... ON CONFLICT DO NOTHING, decided by the affected-row count. Both
// PostgreSQL and SQLite count a matched row as affected even when the value is
// unchanged, so rewriting the same value reports swapped.
func (ls *LocalStorage) CompareAndSetSystemMetadata(ctx context.Context, key, old string, oldFound bool, value string) (bool, error) {
	now := time.Now().UTC()
	var res *gorm.DB
	if oldFound {
		res = ls.db.WithContext(ctx).Model(&models.SystemMetadata{}).
			Where("key = ? AND value = ?", key, old).
			Updates(map[string]any{"value": value, "updated_at": now})
	} else {
		res = ls.db.WithContext(ctx).Clauses(clause.OnConflict{DoNothing: true}).
			Create(&models.SystemMetadata{Key: key, Value: value, UpdatedAt: now})
	}
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected == 1, nil
}
