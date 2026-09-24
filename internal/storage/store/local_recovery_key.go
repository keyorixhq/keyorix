// local_recovery_key.go — the local admin recovery key's verifier record
// (docs/design-b2-recover-admin.md §2), backed by the recovery_key_records
// table. A single singleton row: generation and rotation are the same
// upsert, keyed on the fixed recoveryKeySingletonID.
package store

import (
	"context"
	"errors"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// recoveryKeySingletonID is the fixed primary key of the one recovery-key
// record that ever exists (design §2/§7 Q6: a single recovery key, Shamir
// M-of-N deliberately stays deferred).
const recoveryKeySingletonID = 1

// GetRecoveryKeyRecord returns the local admin recovery key's verifier
// record; found is false on an install that predates this feature or has
// never generated one.
func (ls *LocalStorage) GetRecoveryKeyRecord(ctx context.Context) (*models.RecoveryKeyRecord, bool, error) {
	var rec models.RecoveryKeyRecord
	err := ls.db.WithContext(ctx).Where("id = ?", recoveryKeySingletonID).Take(&rec).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &rec, true, nil
}

// SetRecoveryKeyRecord upserts the singleton recovery-key record. CreatedAt
// is intentionally excluded from DoUpdates: a rotation must never overwrite
// the original generation timestamp, only KeyHash/KeyVersion/RotatedAt.
func (ls *LocalStorage) SetRecoveryKeyRecord(ctx context.Context, record *models.RecoveryKeyRecord) error {
	record.ID = recoveryKeySingletonID
	return ls.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{"key_hash", "key_version", "rotated_at"}),
	}).Create(record).Error
}
