// remote_sod.go — separation-of-duties policies for RemoteStorage. Processed
// server-side; stubs here. See local_sod.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateSoDPolicy(_ context.Context, _ *models.SoDPolicy) (*models.SoDPolicy, error) {
	return nil, remoteUnsupported("CreateSoDPolicy")
}

func (rs *RemoteStorage) GetSoDPolicy(_ context.Context, _ uint) (*models.SoDPolicy, error) {
	return nil, remoteUnsupported("GetSoDPolicy")
}

func (rs *RemoteStorage) ListSoDPolicies(_ context.Context) ([]*models.SoDPolicy, error) {
	return nil, remoteUnsupported("ListSoDPolicies")
}

func (rs *RemoteStorage) DeleteSoDPolicy(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSoDPolicy")
}
