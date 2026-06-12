// remote_mfa.go — MFA persistence is server-side only; the remote client never
// manages MFA state directly (enrolment/verify go through the server's REST API).
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) UpsertMFASecret(_ context.Context, _ *models.MFASecret) error {
	return remoteUnsupported("UpsertMFASecret")
}

func (rs *RemoteStorage) GetMFASecret(_ context.Context, _ uint) (*models.MFASecret, error) {
	return nil, remoteUnsupported("GetMFASecret")
}

func (rs *RemoteStorage) ActivateMFASecret(_ context.Context, _ uint) error {
	return remoteUnsupported("ActivateMFASecret")
}

func (rs *RemoteStorage) DeleteMFAForUser(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteMFAForUser")
}

func (rs *RemoteStorage) SetUserMFAEnabled(_ context.Context, _ uint, _ bool) error {
	return remoteUnsupported("SetUserMFAEnabled")
}

func (rs *RemoteStorage) CreateMFARecoveryCodes(_ context.Context, _ uint, _ []string) error {
	return remoteUnsupported("CreateMFARecoveryCodes")
}

func (rs *RemoteStorage) ConsumeMFARecoveryCode(_ context.Context, _ uint, _ string, _ time.Time) (bool, error) {
	return false, remoteUnsupported("ConsumeMFARecoveryCode")
}

func (rs *RemoteStorage) CreateMFAChallenge(_ context.Context, _ *models.MFAChallenge) error {
	return remoteUnsupported("CreateMFAChallenge")
}

func (rs *RemoteStorage) ConsumeMFAChallenge(_ context.Context, _ string, _ time.Time) (*models.MFAChallenge, error) {
	return nil, remoteUnsupported("ConsumeMFAChallenge")
}
