// local_stats.go — Stats and health operations for LocalStorage.
//
// Covers: GetStats, SaveStatsSnapshot, GetPreviousStatsSnapshot,
// SaveDeploymentStatsSnapshot, GetPreviousDeploymentStatsSnapshot, HealthCheck.
//
// All operations use direct GORM queries.
// For the remote (HTTP) equivalent see remote_stats.go.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// GetStats aggregates row counts for the key entity types. #G54: each Count's
// error is checked and propagated — previously a failed query silently left
// its field at Go's zero value, so a genuine storage error (a missing table,
// a connectivity blip) was indistinguishable from an honestly-empty
// deployment, fabricating a "0 secrets, 0 users" success result for any
// dashboard/health consumer of this call.
func (ls *LocalStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	stats := &storage.StorageStats{}
	if err := ls.db.WithContext(ctx).Model(&models.SecretNode{}).Count(&stats.TotalSecrets).Error; err != nil {
		return nil, err
	}
	if err := ls.db.WithContext(ctx).Model(&models.User{}).Count(&stats.TotalUsers).Error; err != nil {
		return nil, err
	}
	if err := ls.db.WithContext(ctx).Model(&models.Role{}).Count(&stats.TotalRoles).Error; err != nil {
		return nil, err
	}
	if err := ls.db.WithContext(ctx).Model(&models.Session{}).Count(&stats.TotalSessions).Error; err != nil {
		return nil, err
	}
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

// SaveDeploymentStatsSnapshot persists a deployment-wide stats snapshot.
func (ls *LocalStorage) SaveDeploymentStatsSnapshot(ctx context.Context, snap *models.DeploymentStatsSnapshot) error {
	return ls.db.WithContext(ctx).Create(snap).Error
}

// GetPreviousDeploymentStatsSnapshot returns the most recent deployment stats
// snapshot older than 20 hours. Returns nil, nil if none exists.
func (ls *LocalStorage) GetPreviousDeploymentStatsSnapshot(ctx context.Context) (*models.DeploymentStatsSnapshot, error) {
	cutoff := time.Now().UTC().Add(-20 * time.Hour)
	var snap models.DeploymentStatsSnapshot
	err := ls.db.WithContext(ctx).
		Where("snapshot_date < ?", cutoff).
		Order("snapshot_date DESC").
		First(&snap).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &snap, nil
}

// HealthCheck verifies the database is reachable with a lightweight SELECT 1.
func (ls *LocalStorage) HealthCheck(ctx context.Context) error {
	var result int
	return ls.db.WithContext(ctx).Raw("SELECT 1").Scan(&result).Error
}
