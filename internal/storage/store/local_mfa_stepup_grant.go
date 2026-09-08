// local_mfa_stepup_grant.go — MFAStepUpGrant persistence for LocalStorage.
// Each VerifyMFAStepUp call creates a new grant row; queries return the most
// recent non-expired one. Expired rows are kept for audit purposes, bounded by
// the PruneMFAStepUpGrants maintenance sweep (store-mfa-002) rather than kept
// indefinitely — see internal/core.KeyorixCore.PruneMFAStepUpGrants and its
// scheduler wiring in server/main.go (mfa_stepup_grant_prune).
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func (ls *LocalStorage) CreateMFAStepUpGrant(ctx context.Context, grant *models.MFAStepUpGrant) error {
	return ls.db.WithContext(ctx).Create(grant).Error
}

func (ls *LocalStorage) GetActiveMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (*models.MFAStepUpGrant, error) {
	var g models.MFAStepUpGrant
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?", userID, purpose, now.UTC()).
		Order("expires_at DESC").
		First(&g).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &g, nil
}

// ConsumeMFAStepUpGrant atomically marks every live (unconsumed, unexpired)
// grant for (userID, purpose) as consumed via a single conditional UPDATE —
// the same no-read-then-write-race shape as ConsumeMFARecoveryCode/
// ConsumeWebAuthnSession, so two near-simultaneous callers racing the same
// live grant can never both see RowsAffected > 0. Reports whether any grant
// was found (and thus consumed).
//
// Marking ALL matching rows (not just the newest) rather than selecting one
// specific row is deliberate: there should only ever be one live
// MFAStepUpPurposeReauth grant per user in practice (each FinishWebAuthnReauth
// mints a fresh one), but if more than one somehow coexists, single-use means
// none of them may go on to authorize a second action either.
func (ls *LocalStorage) ConsumeMFAStepUpGrant(ctx context.Context, userID uint, purpose models.MFAStepUpPurpose, now time.Time) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.MFAStepUpGrant{}).
		Where("user_id = ? AND purpose = ? AND consumed_at IS NULL AND expires_at > ?", userID, purpose, now.UTC()).
		Update("consumed_at", now.UTC())
	if res.Error != nil {
		return false, res.Error
	}
	return res.RowsAffected > 0, nil
}

func (ls *LocalStorage) DeleteMFAStepUpGrantsFor(ctx context.Context, userID uint) error {
	return ls.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&models.MFAStepUpGrant{}).Error
}

// PruneMFAStepUpGrants deletes grants whose ExpiresAt predates `before` and
// returns how many were removed (store-mfa-002 maintenance sweep — see
// internal/core.KeyorixCore.PruneMFAStepUpGrants, the sole intended caller).
//
// G81 (ExpiresAt, this file's third recurrence): normalize `before` internally
// rather than trusting the caller — see GetAuditLogs. core.KeyorixCore's cutoff
// is derived from time.Now() (server-local, not guaranteed UTC), while
// MFAStepUpGrant.BeforeSave always normalizes ExpiresAt to UTC before writing;
// on SQLite (plain string comparison) a non-UTC `before` silently drifts from
// what's actually stored whenever the server process isn't pinned to TZ=UTC.
func (ls *LocalStorage) PruneMFAStepUpGrants(ctx context.Context, before time.Time) (int64, error) {
	res := ls.db.WithContext(ctx).Where("expires_at < ?", before.UTC()).Delete(&models.MFAStepUpGrant{})
	return res.RowsAffected, res.Error
}
