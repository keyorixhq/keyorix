// remote_stats.go — Stats and health operations for RemoteStorage.
//
// Covers: GetStats, SaveStatsSnapshot (no-op), GetPreviousStatsSnapshot (unsupported),
//
//	Health, HealthCheck.
//
// Stats snapshots are managed server-side; only GetStats proxies to the API.
// For the local (GORM) equivalent see local_stats.go.
package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetStats retrieves storage statistics via remote API.
func (rs *RemoteStorage) GetStats(ctx context.Context) (*storage.StorageStats, error) {
	resp, err := rs.client.Get(ctx, "/api/v1/stats")
	if err != nil {
		return nil, fmt.Errorf("failed to get stats: %w", err)
	}
	if !resp.Success {
		return nil, fmt.Errorf("get stats failed: %s", resp.Error.Error())
	}
	var result storage.StorageStats
	if err := json.Unmarshal(resp.Data, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &result, nil
}

// SaveStatsSnapshot is a no-op in remote mode — snapshots are managed server-side.
func (rs *RemoteStorage) SaveStatsSnapshot(_ context.Context, _ *models.StatsSnapshot) error {
	return nil
}

// GetPreviousStatsSnapshot is not supported in remote mode.
func (rs *RemoteStorage) GetPreviousStatsSnapshot(_ context.Context, _ uint) (*models.StatsSnapshot, error) {
	return nil, fmt.Errorf("stats snapshots not available in remote mode")
}

// Health checks whether the remote Keyorix server is reachable.
func (rs *RemoteStorage) Health(ctx context.Context) error {
	resp, err := rs.client.Get(ctx, "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("health check failed: %s", resp.Error.Error())
	}
	return nil
}

// HealthCheck is an alias for Health, satisfying the storage.Storage interface.
func (rs *RemoteStorage) HealthCheck(ctx context.Context) error {
	return rs.Health(ctx)
}
