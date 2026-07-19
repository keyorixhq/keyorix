// remote_secret_schedule.go — SecretAccessSchedule stubs for RemoteStorage (temporal access policies).
// The schedule check runs server-side; a CLI remote caller never invokes these directly.
// Schedule management routes (GET/PUT/DELETE /api/v1/secrets/{id}/schedule) are
// reached via the HTTP handlers in server/http/handlers/secret_schedule.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) GetSecretAccessSchedule(_ context.Context, _ uint) (*models.SecretAccessSchedule, error) {
	return nil, remoteUnsupported("GetSecretAccessSchedule")
}

func (rs *RemoteStorage) SetSecretAccessSchedule(_ context.Context, _ *models.SecretAccessSchedule) error {
	return remoteUnsupported("SetSecretAccessSchedule")
}

func (rs *RemoteStorage) DeleteSecretAccessSchedule(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretAccessSchedule")
}
