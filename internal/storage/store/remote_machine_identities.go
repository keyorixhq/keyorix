// remote_machine_identities.go — machine identities for RemoteStorage (ADR-023).
//
// Machine identity management is processed server-side in remote mode; stubs.
// For the local (GORM) equivalent see local_machine_identities.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateMachineIdentity(_ context.Context, _ *models.MachineIdentity) (*models.MachineIdentity, error) {
	return nil, fmt.Errorf("CreateMachineIdentity not implemented for remote storage")
}

func (rs *RemoteStorage) GetMachineIdentity(_ context.Context, _ uint) (*models.MachineIdentity, error) {
	return nil, fmt.Errorf("GetMachineIdentity not implemented for remote storage")
}

func (rs *RemoteStorage) UpdateMachineIdentity(_ context.Context, _ *models.MachineIdentity) error {
	return fmt.Errorf("UpdateMachineIdentity not implemented for remote storage")
}

func (rs *RemoteStorage) ListMachineIdentities(_ context.Context, _ uint) ([]*models.MachineIdentity, error) {
	return nil, fmt.Errorf("ListMachineIdentities not implemented for remote storage")
}
