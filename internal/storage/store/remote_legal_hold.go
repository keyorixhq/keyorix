// remote_legal_hold.go — legal hold for RemoteStorage. Processed server-side;
// stubs here. See local_legal_hold.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateLegalHold(_ context.Context, _ *models.LegalHold) (*models.LegalHold, error) {
	return nil, remoteUnsupported("CreateLegalHold")
}

func (rs *RemoteStorage) GetActiveLegalHold(_ context.Context) (*models.LegalHold, error) {
	return nil, remoteUnsupported("GetActiveLegalHold")
}

func (rs *RemoteStorage) UpdateLegalHold(_ context.Context, _ *models.LegalHold) error {
	return remoteUnsupported("UpdateLegalHold")
}
