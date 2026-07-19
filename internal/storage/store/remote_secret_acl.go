// remote_secret_acl.go — SecretACL stubs for RemoteStorage (RBAC Phase 3).
// These operations are currently not proxied over HTTP; they return ErrRemoteUnsupported.
// A future PR may add proxy routes under /api/v1/system/secret-acls.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateOrUpdateSecretACL(_ context.Context, _ *models.SecretACL) error {
	return remoteUnsupported("CreateOrUpdateSecretACL")
}

func (rs *RemoteStorage) ListSecretACLs(_ context.Context, _ uint) ([]*models.SecretACL, error) {
	return nil, remoteUnsupported("ListSecretACLs")
}

func (rs *RemoteStorage) GetSecretACL(_ context.Context, _, _ uint) (*models.SecretACL, error) {
	return nil, remoteUnsupported("GetSecretACL")
}

func (rs *RemoteStorage) DeleteSecretACL(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretACL")
}
