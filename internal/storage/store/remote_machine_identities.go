// remote_machine_identities.go — machine identities for RemoteStorage (ADR-023).
//
// Machine identity management is processed server-side in remote mode; stubs.
// For the local (GORM) equivalent see local_machine_identities.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateMachineIdentity(_ context.Context, _ *models.MachineIdentity) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("CreateMachineIdentity")
}

func (rs *RemoteStorage) GetMachineIdentity(_ context.Context, _ uint) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("GetMachineIdentity")
}

func (rs *RemoteStorage) LockMachineIdentityForUpdate(_ context.Context, _ uint) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("LockMachineIdentityForUpdate")
}

func (rs *RemoteStorage) UpdateMachineIdentity(_ context.Context, _ *models.MachineIdentity) error {
	return remoteUnsupported("UpdateMachineIdentity")
}

func (rs *RemoteStorage) ListMachineIdentities(_ context.Context, _ uint) ([]*models.MachineIdentity, error) {
	return nil, remoteUnsupported("ListMachineIdentities")
}

func (rs *RemoteStorage) ListAllMachineIdentities(_ context.Context) ([]*models.MachineIdentity, error) {
	return nil, remoteUnsupported("ListAllMachineIdentities")
}

func (rs *RemoteStorage) CountMachineIdentitiesByClassification(_ context.Context) (map[string]int, error) {
	return nil, remoteUnsupported("CountMachineIdentitiesByClassification")
}

func (rs *RemoteStorage) CreateMachineIdentityCredential(_ context.Context, _ *models.MachineIdentityCredential) (*models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("CreateMachineIdentityCredential")
}

func (rs *RemoteStorage) GetMachineIdentityCredentialByHash(_ context.Context, _ string) (*models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("GetMachineIdentityCredentialByHash")
}

func (rs *RemoteStorage) GetMachineIdentityCredentialByID(_ context.Context, _ uint) (*models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("GetMachineIdentityCredentialByID")
}

func (rs *RemoteStorage) ListMachineIdentityCredentials(_ context.Context, _ uint) ([]*models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("ListMachineIdentityCredentials")
}

func (rs *RemoteStorage) ListActiveMachineIdentityCredentials(_ context.Context) ([]*models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("ListActiveMachineIdentityCredentials")
}

func (rs *RemoteStorage) UpdateMachineIdentityCredential(_ context.Context, _ *models.MachineIdentityCredential) error {
	return remoteUnsupported("UpdateMachineIdentityCredential")
}

func (rs *RemoteStorage) CountMachineIdentityCredentialsByClassification(_ context.Context) (map[string]int, error) {
	return nil, remoteUnsupported("CountMachineIdentityCredentialsByClassification")
}

func (rs *RemoteStorage) RevokeMachineIdentityCredential(_ context.Context, _ uint) error {
	return remoteUnsupported("RevokeMachineIdentityCredential")
}

func (rs *RemoteStorage) TouchMachineIdentityCredential(_ context.Context, _ uint, _ time.Time, _ time.Duration) error {
	return remoteUnsupported("TouchMachineIdentityCredential")
}

func (rs *RemoteStorage) AssignMachineRole(_ context.Context, _, _ uint, _ storage.Scope) error {
	return remoteUnsupported("AssignMachineRole")
}

func (rs *RemoteStorage) RemoveMachineRole(_ context.Context, _, _ uint, _ storage.Scope) error {
	return remoteUnsupported("RemoveMachineRole")
}

func (rs *RemoteStorage) GetMachineRoleIDsAt(_ context.Context, _ uint, _ storage.Scope) ([]uint, error) {
	return nil, remoteUnsupported("GetMachineRoleIDsAt")
}

func (rs *RemoteStorage) GetMachineRoles(_ context.Context, _ uint) ([]*models.Role, error) {
	return nil, remoteUnsupported("GetMachineRoles")
}

func (rs *RemoteStorage) CreateOIDCBinding(_ context.Context, _ *models.MachineIdentityOIDCBinding) (*models.MachineIdentityOIDCBinding, error) {
	return nil, remoteUnsupported("CreateOIDCBinding")
}

func (rs *RemoteStorage) GetMachineByOIDCSubject(_ context.Context, _, _ string) (*models.MachineIdentity, error) {
	return nil, remoteUnsupported("GetMachineByOIDCSubject")
}

func (rs *RemoteStorage) ListOIDCBindings(_ context.Context, _ uint) ([]*models.MachineIdentityOIDCBinding, error) {
	return nil, remoteUnsupported("ListOIDCBindings")
}

func (rs *RemoteStorage) GetOIDCBindingByID(_ context.Context, _ uint) (*models.MachineIdentityOIDCBinding, error) {
	return nil, remoteUnsupported("GetOIDCBindingByID")
}

func (rs *RemoteStorage) DeleteOIDCBinding(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteOIDCBinding")
}
