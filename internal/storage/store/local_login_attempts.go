// local_login_attempts.go — cluster-wide login rate limiting (ADR-040). Failed
// attempts are recorded per IP; a windowed count gates further attempts across all
// replicas, and a maintenance sweep prunes rows past the window.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) RecordLoginAttempt(ctx context.Context, ip string, at time.Time) error {
	return ls.db.WithContext(ctx).Create(&models.LoginAttempt{IP: ip, AttemptedAt: at}).Error
}

func (ls *LocalStorage) CountRecentLoginAttempts(ctx context.Context, ip string, since time.Time) (int64, error) {
	// G81 (LoginAttempt.AttemptedAt): normalize internally — see GetAuditLogs. A
	// cross-process write (login_attempts_proxy.go, storage.type: remote) carries
	// a follower's own local clock across the wire, so this bound can genuinely
	// diverge from a write's Location, not just drift within one process.
	since = since.UTC()
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.LoginAttempt{}).
		Where("ip = ? AND attempted_at > ?", ip, since).Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

// PruneLoginAttempts deletes attempts older than `before` (past the window) and
// returns how many were removed.
func (ls *LocalStorage) PruneLoginAttempts(ctx context.Context, before time.Time) (int64, error) {
	// G81 (LoginAttempt.AttemptedAt): normalize internally — see GetAuditLogs.
	before = before.UTC()
	res := ls.db.WithContext(ctx).Where("attempted_at < ?", before).Delete(&models.LoginAttempt{})
	return res.RowsAffected, res.Error
}

// ReserveLoginAttempt is RecordLoginAttempt plus returning the new row's id —
// see the Storage interface doc for why only one caller needs this.
func (ls *LocalStorage) ReserveLoginAttempt(ctx context.Context, ip string, at time.Time) (uint, error) {
	row := &models.LoginAttempt{IP: ip, AttemptedAt: at}
	if err := ls.db.WithContext(ctx).Create(row).Error; err != nil {
		return 0, err
	}
	return row.ID, nil
}

// ReleaseLoginAttempt undoes a ReserveLoginAttempt write. Deleting zero rows
// (already gone) is not an error — GORM's Delete only errors on a genuine
// storage failure, not on a missing row.
func (ls *LocalStorage) ReleaseLoginAttempt(ctx context.Context, id uint) error {
	return ls.db.WithContext(ctx).Delete(&models.LoginAttempt{}, id).Error
}
