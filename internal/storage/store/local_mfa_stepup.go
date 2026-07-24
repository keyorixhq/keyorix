// local_mfa_stepup.go — MFA step-up token persistence for LocalStorage.
// One row per user (uniqueIndex on user_id); UpsertMFAStepupToken replaces it
// on each re-verification using ON CONFLICT, mirroring local_mfa.go's
// UpsertMFASecret pattern exactly.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

const sqlWhereUserIDAndNotExpired = "user_id = ? AND expires_at > ?"

// UpsertMFAStepupToken inserts or replaces the step-up record for userID,
// setting its expiry to expiresAt. A second MFA verification within the window
// extends the window cleanly (ON CONFLICT updates expires_at in place).
func (ls *LocalStorage) UpsertMFAStepupToken(ctx context.Context, userID uint, expiresAt time.Time) error {
	tok := &models.MFAStepupToken{UserID: userID, ExpiresAt: expiresAt}
	return ls.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns:   []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{"expires_at": expiresAt}),
	}).Create(tok).Error
}

// HasActiveMFAStepup reports whether userID has a non-expired step-up record —
// i.e., that they completed MFA verification within the configured window.
// Returns (false, nil) when no record exists or the record has expired.
func (ls *LocalStorage) HasActiveMFAStepup(ctx context.Context, userID uint) (bool, error) {
	var tok models.MFAStepupToken
	err := ls.db.WithContext(ctx).
		Where(sqlWhereUserIDAndNotExpired, userID, time.Now()).
		First(&tok).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return err == nil, err
}
