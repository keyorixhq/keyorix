package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetAnomalyConfig is not supported on RemoteStorage; anomaly config is managed
// server-side via the /api/v1/admin/anomaly-config REST endpoint.
func (rs *RemoteStorage) GetAnomalyConfig(_ context.Context) (*models.AnomalyConfigRecord, error) {
	return nil, remoteUnsupported("GetAnomalyConfig")
}

// SaveAnomalyConfig is not supported on RemoteStorage; anomaly config is managed
// server-side via the /api/v1/admin/anomaly-config REST endpoint.
func (rs *RemoteStorage) SaveAnomalyConfig(_ context.Context, _ *models.AnomalyConfigRecord) error {
	return remoteUnsupported("SaveAnomalyConfig")
}
