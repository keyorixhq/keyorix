// local_compliance_snapshot.go — CompliancePostureSnapshot persistence for LocalStorage.
//
// Covers: SaveCompliancePostureSnapshot, GetPreviousCompliancePostureSnapshot.
//
// For the remote (stub) equivalent see remote_compliance.go.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// SaveCompliancePostureSnapshot upserts a daily compliance posture snapshot.
// If a row already exists for the given SnapshotDate it is updated in-place;
// otherwise a new row is created.
func (ls *LocalStorage) SaveCompliancePostureSnapshot(ctx context.Context, snap *models.CompliancePostureSnapshot) error {
	return ls.db.WithContext(ctx).
		Where(models.CompliancePostureSnapshot{SnapshotDate: snap.SnapshotDate}).
		Assign(*snap).
		FirstOrCreate(snap).Error
}

// GetPreviousCompliancePostureSnapshot returns the most recent snapshot whose
// snapshot_date is strictly before today's UTC midnight — i.e., from a prior
// calendar day. This avoids same-day self-comparison regardless of the time of
// day the posture endpoint is called.
// Returns nil, nil when no prior snapshot exists.
func (ls *LocalStorage) GetPreviousCompliancePostureSnapshot(ctx context.Context) (*models.CompliancePostureSnapshot, error) {
	now := time.Now().UTC()
	todayMidnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var snap models.CompliancePostureSnapshot
	err := ls.db.WithContext(ctx).
		Where("snapshot_date < ?", todayMidnight).
		Order("snapshot_date DESC").
		First(&snap).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &snap, err
}
