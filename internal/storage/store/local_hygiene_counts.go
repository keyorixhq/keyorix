// local_hygiene_counts.go — credential-hygiene trend count queries for LocalStorage.
//
// Covers: SaveHygieneTrendSnapshot, ListHygieneTrendSnapshots,
// CountStalePATs, CountExpiredPATs, CountStaleMachineCredentials.
//
// For the remote (stub) equivalent see remote_hygiene_counts.go.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// SaveHygieneTrendSnapshot upserts a daily hygiene trend snapshot. If a row
// already exists for the given SnapshotDate it is updated in-place; otherwise
// a new row is created.
func (ls *LocalStorage) SaveHygieneTrendSnapshot(ctx context.Context, snap *models.HygieneTrendSnapshot) error {
	return ls.db.WithContext(ctx).
		Where(models.HygieneTrendSnapshot{SnapshotDate: snap.SnapshotDate}).
		Assign(*snap).
		FirstOrCreate(snap).Error
}

// ListHygieneTrendSnapshots returns up to `days` snapshots ordered by
// snapshot_date DESC (newest first).
func (ls *LocalStorage) ListHygieneTrendSnapshots(ctx context.Context, days int) ([]*models.HygieneTrendSnapshot, error) {
	if days <= 0 {
		days = 30
	}
	var snaps []*models.HygieneTrendSnapshot
	err := ls.db.WithContext(ctx).
		Order("snapshot_date DESC").
		Limit(days).
		Find(&snaps).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return snaps, err
}

// CountStalePATs returns the count of non-revoked, active (not expired) PATs
// that have not been used since threshold (or never used).
func (ls *LocalStorage) CountStalePATs(ctx context.Context, threshold time.Time) (int, error) {
	// G81 (PersonalAccessToken.ExpiresAt): normalize the expires_at bound
	// internally — see GetAuditLogs. last_used_at (threshold) is intentionally
	// left as-is: its sole write path (TouchPersonalAccessToken) bypasses model
	// hooks via UpdateColumn, so it's a separate, currently-latent hazard tracked
	// in #1507, not fixed here.
	var count int64
	err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("revoked = ? AND (expires_at IS NULL OR expires_at > ?) AND (last_used_at IS NULL OR last_used_at < ?)",
			false, time.Now().UTC(), threshold).
		Count(&count).Error
	return int(count), err
}

// CountExpiredPATs returns the count of non-revoked PATs whose ExpiresAt is
// in the past (expired but never explicitly revoked — token sprawl).
func (ls *LocalStorage) CountExpiredPATs(ctx context.Context) (int, error) {
	// G81 (PersonalAccessToken.ExpiresAt): normalize internally — see GetAuditLogs.
	var count int64
	err := ls.db.WithContext(ctx).Model(&models.PersonalAccessToken{}).
		Where("revoked = ? AND expires_at IS NOT NULL AND expires_at < ?", false, time.Now().UTC()).
		Count(&count).Error
	return int(count), err
}

// CountStaleMachineCredentials returns the count of active machine identities
// that have no credential used since threshold (or no credential at all).
// An active machine identity is "stale" when its most-recent credential
// LastUsedAt is NULL or before threshold.
func (ls *LocalStorage) CountStaleMachineCredentials(ctx context.Context, threshold time.Time) (int, error) {
	// #1507 (MachineIdentityCredential.LastUsedAt): last_used_at's sole write
	// path (TouchMachineIdentityCredential) bypasses model hooks via
	// UpdateColumn, so this range query is safe only as long as threshold and
	// the write both keep coming from the same c.now() accessor — see
	// TouchMachineIdentityCredential's own #1507 comment (local_machine_credentials.go)
	// for the normalization point if that ever stops being true. Same shape as
	// CountStalePATs's #1507 comment just below for PersonalAccessToken.LastUsedAt.
	//
	// Subquery: machine identity IDs that have at least one credential used
	// since threshold (i.e. NOT stale).
	// We count active machine identities NOT in that set.
	var count int64
	err := ls.db.WithContext(ctx).
		Table("machine_identities mi").
		Where("mi.state = ?", "active").
		Where("mi.id NOT IN (?)",
			ls.db.WithContext(ctx).
				Table("machine_identity_credentials mic").
				Select("mic.machine_identity_id").
				Where("mic.revoked = ? AND mic.last_used_at IS NOT NULL AND mic.last_used_at >= ?", false, threshold),
		).
		Count(&count).Error
	return int(count), err
}
