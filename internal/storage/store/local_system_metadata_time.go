// local_system_metadata_time.go — the last-write time of a system_metadata row.
//
// Deliberately NOT a method of the Storage interface (it is on the hot path's
// contract; every wrapper and fault double would have to carry it): callers that
// want it ask for this optional interface, SystemMetadataTimes, and fall back
// when the backend does not provide it.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// SystemMetadataTimes is implemented by storage backends that can report when a
// system_metadata key was last written.
type SystemMetadataTimes interface {
	// SystemMetadataUpdatedAt returns the row's updated_at; found is false when the
	// key has never been set.
	SystemMetadataUpdatedAt(ctx context.Context, key string) (updatedAt time.Time, found bool, err error)
}

// SystemMetadataUpdatedAt implements SystemMetadataTimes.
func (ls *LocalStorage) SystemMetadataUpdatedAt(ctx context.Context, key string) (time.Time, bool, error) {
	var m models.SystemMetadata
	err := ls.db.WithContext(ctx).Select("key", "updated_at").Where("key = ?", key).Take(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	return m.UpdatedAt.UTC(), true, nil
}

var _ SystemMetadataTimes = (*LocalStorage)(nil)
