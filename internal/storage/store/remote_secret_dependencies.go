// remote_secret_dependencies.go — secret dependency edges for RemoteStorage.
// Processed server-side; stubs here. See local_secret_dependencies.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateSecretDependency(_ context.Context, _ *models.SecretDependency) (*models.SecretDependency, error) {
	return nil, remoteUnsupported("CreateSecretDependency")
}

func (rs *RemoteStorage) GetSecretDependency(_ context.Context, _ uint) (*models.SecretDependency, error) {
	return nil, remoteUnsupported("GetSecretDependency")
}

func (rs *RemoteStorage) ListSecretDependenciesForProject(_ context.Context, _ uint) ([]*models.SecretDependency, error) {
	return nil, remoteUnsupported("ListSecretDependenciesForProject")
}

func (rs *RemoteStorage) DeleteSecretDependency(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretDependency")
}
