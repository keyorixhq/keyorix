// remote_dynamic.go — dynamic secrets are a server-side capability; the remote
// client manages them through the REST API, not the storage interface directly.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateDynamicSecretConfig(_ context.Context, _ *models.DynamicSecretConfig) (*models.DynamicSecretConfig, error) {
	return nil, remoteUnsupported("CreateDynamicSecretConfig")
}
func (rs *RemoteStorage) GetDynamicSecretConfig(_ context.Context, _ uint) (*models.DynamicSecretConfig, error) {
	return nil, remoteUnsupported("GetDynamicSecretConfig")
}
func (rs *RemoteStorage) ListDynamicSecretConfigs(_ context.Context, _, _ uint) ([]*models.DynamicSecretConfig, error) {
	return nil, remoteUnsupported("ListDynamicSecretConfigs")
}
func (rs *RemoteStorage) UpdateDynamicSecretConfig(_ context.Context, _ *models.DynamicSecretConfig) error {
	return remoteUnsupported("UpdateDynamicSecretConfig")
}
func (rs *RemoteStorage) CountDynamicSecretConfigsByClassification(_ context.Context) (map[string]int, error) {
	return nil, remoteUnsupported("CountDynamicSecretConfigsByClassification")
}
func (rs *RemoteStorage) CreateDynamicSecretLease(_ context.Context, _ *models.DynamicSecretLease) (*models.DynamicSecretLease, error) {
	return nil, remoteUnsupported("CreateDynamicSecretLease")
}
func (rs *RemoteStorage) GetDynamicSecretLease(_ context.Context, _ string) (*models.DynamicSecretLease, error) {
	return nil, remoteUnsupported("GetDynamicSecretLease")
}
func (rs *RemoteStorage) ListDynamicSecretLeases(_ context.Context, _ uint) ([]*models.DynamicSecretLease, error) {
	return nil, remoteUnsupported("ListDynamicSecretLeases")
}
func (rs *RemoteStorage) CountActiveLeases(_ context.Context, _ uint) (int64, error) {
	return 0, remoteUnsupported("CountActiveLeases")
}
func (rs *RemoteStorage) UpdateDynamicSecretLease(_ context.Context, _ *models.DynamicSecretLease) error {
	return remoteUnsupported("UpdateDynamicSecretLease")
}
func (rs *RemoteStorage) ListExpiredActiveLeases(_ context.Context, _ time.Time) ([]*models.DynamicSecretLease, error) {
	return nil, remoteUnsupported("ListExpiredActiveLeases")
}
