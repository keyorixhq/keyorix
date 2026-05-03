// local_stats.go — Stats and health operations for LocalStorage.
//
// Covers: GetStats, SaveStatsSnapshot, GetPreviousStatsSnapshot, HealthCheck.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_stats.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetStats aggregates row counts for the key entity types.
func (ls *LocalStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	stats := &storage.StorageStats{}
	ls.db.WithContext(ctx).Model(&models.SecretNode{}).Count(&stats.TotalSecrets)
	ls.db.WithContext(ctx).Model(&models.User{}).Count(&stats.TotalUsers)
	ls.db.WithContext(ctx).Model(&models.Role{}).Count(&stats.TotalRoles)
	ls.db.WithContext(ctx).Model(&models.Session{}).Count(&stats.TotalSessions)
	return stats, nil
}

// SaveStatsSnapshot persists a stats snapshot for trend / delta calculations.
func (ls *LocalStorage) SaveStatsSnapshot(ctx context.Context, snapshot *models.StatsSnapshot) error {
	return ls.db.WithContext(ctx).Create(snapshot).Error
}

// GetPreviousStatsSnapshot returns the most recent snapshot older than 20 hours for userID.
// The 20-hour window ensures "yesterday's" snapshot is returned without clock-drift issues.
func (ls *LocalStorage) GetPreviousStatsSnapshot(ctx context.Context, userID uint) (*models.StatsSnapshot, error) {
	var snapshot models.StatsSnapshot
	cutoff := time.Now().Add(-20 * time.Hour)
	err := ls.db.WithContext(ctx).
		Where("user_id = ? AND created_at < ?", userID, cutoff).
		Order("created_at DESC").
		First(&snapshot).Error
	if err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// HealthCheck verifies the database is reachable with a lightweight SELECT 1.
func (ls *LocalStorage) HealthCheck(ctx context.Context) error {
	var result int
	return ls.db.WithContext(ctx).Raw("SELECT 1").Scan(&result).Error
}
