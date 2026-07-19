// remote_secret_acl.go — SecretACL stubs for RemoteStorage (RBAC Phase 3).
// These operations are currently not proxied over HTTP; they return ErrRemoteUnsupported.
// A future PR may add proxy routes under /api/v1/system/secret-acls.
//
// GetSecretAncestors returns ErrUnsupportedByBackend so the core ancestor walk
// in HasSecretACL skips folder-inheritance checks on remote callers — the server
// already enforces them locally before returning a response to the CLI.
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

func (rs *RemoteStorage) ListSecretACLsByUser(_ context.Context, _ uint) ([]*models.SecretACL, error) {
	return nil, remoteUnsupported("ListSecretACLsByUser")
}

func (rs *RemoteStorage) GetSecretACL(_ context.Context, _, _ uint) (*models.SecretACL, error) {
	return nil, remoteUnsupported("GetSecretACL")
}

func (rs *RemoteStorage) DeleteSecretACL(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteSecretACL")
}

// GetSecretAncestors is the folder-ACL inheritance walk helper. Folder-ACL
// enforcement is server-side only; the inheritance walk in HasSecretACL skips
// this path when ErrUnsupportedByBackend is returned.
func (rs *RemoteStorage) GetSecretAncestors(_ context.Context, _ uint) ([]uint, error) {
	return nil, remoteUnsupported("GetSecretAncestors")
}
