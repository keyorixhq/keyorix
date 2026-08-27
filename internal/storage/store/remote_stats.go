// remote_stats.go — Stats and health operations for RemoteStorage.
//
// Covers: GetStats, SaveStatsSnapshot (no-op), GetPreviousStatsSnapshot (unsupported),
// SaveDeploymentStatsSnapshot (unsupported), GetPreviousDeploymentStatsSnapshot (unsupported),
// Health, HealthCheck.
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

// SaveDeploymentStatsSnapshot is not supported in remote mode — deployment
// stats snapshots are saved server-side in GetDashboardStats.
func (rs *RemoteStorage) SaveDeploymentStatsSnapshot(_ context.Context, _ *models.DeploymentStatsSnapshot) error {
	return remoteUnsupported("SaveDeploymentStatsSnapshot")
}

// GetPreviousDeploymentStatsSnapshot is not supported in remote mode — the
// trend is computed server-side in core.GetDashboardStats.
func (rs *RemoteStorage) GetPreviousDeploymentStatsSnapshot(_ context.Context) (*models.DeploymentStatsSnapshot, error) {
	return nil, remoteUnsupported("GetPreviousDeploymentStatsSnapshot")
}

// Health checks whether the remote Keyorix server is reachable.
//
// G80 Wave 0c: unlike every other RemoteStorage call, /health is NOT an
// /api/v1/* route and does not use the {"success":...,"data":...} envelope —
// it's an unauthenticated, k8s-probe-style liveness endpoint (same convention
// as its sibling /readyz), deliberately minimal by design
// (server/http/handlers/health.go), returning a raw
// {"status":"healthy","timestamp":...,"uptime":...} body. Checking resp.Success
// here was wrong: unmarshaling that body into APIResponse succeeds (its fields
// are all optional) but leaves Success at its zero value false, so this method
// reported every genuinely healthy server as unhealthy
// ("UPSTREAM_UNSUCCESSFUL: upstream returned an unsuccessful response with no
// error detail") — confirmed live against a real server. rs.client.Get already
// treats any 4xx/5xx as an error (see HTTPClient.makeRequest), so err == nil
// here already means a 2xx round trip; that alone is the correct signal for
// this one non-enveloped endpoint.
func (rs *RemoteStorage) Health(ctx context.Context) error {
	_, err := rs.client.Get(ctx, "/health")
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	return nil
}

// HealthCheck is an alias for Health, satisfying the storage.Storage interface.
func (rs *RemoteStorage) HealthCheck(ctx context.Context) error {
	return rs.Health(ctx)
}
