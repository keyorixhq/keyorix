// remote_machine_identities.go — machine identities for RemoteStorage (ADR-023).
//
// Machine identity management is processed server-side in remote mode; stubs.
// For the local (GORM) equivalent see local_machine_identities.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateMachineIdentity(_ context.Context, _ *models.MachineIdentity) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("CreateMachineIdentity")
}

func (rs *RemoteStorage) GetMachineIdentity(_ context.Context, _ uint) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("GetMachineIdentity")
}

func (rs *RemoteStorage) UpdateMachineIdentity(_ context.Context, _ *models.MachineIdentity) error {
	return remoteUnsupported("UpdateMachineIdentity")
}

func (rs *RemoteStorage) ListMachineIdentities(_ context.Context, _ uint) ([]*models.MachineIdentity, error) {
	return nil, remoteUnsupported("ListMachineIdentities")
}
