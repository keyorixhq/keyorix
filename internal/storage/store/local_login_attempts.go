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
