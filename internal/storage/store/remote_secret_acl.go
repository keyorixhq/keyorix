// remote_secret_acl.go — SecretACL stubs for RemoteStorage (RBAC Phase 3).
// Most of these operations are not proxied over HTTP; they return
// ErrRemoteUnsupported (core.aclGrantsPermission treats this the same as
// "no grant" — it does not fail secret authorization closed). A future PR
// may add proxy routes for the rest under /api/v1/system/secret-acls.
//
// GetSecretAncestors returns ErrUnsupportedByBackend so the core ancestor walk
// in HasSecretACL skips folder-inheritance checks on remote callers — the server
// already enforces them locally before returning a response to the CLI.
//
// #G13: DeleteSecretACLsByUserAndProject IS proxied — unlike the others, this
// one is a security-relevant CLEANUP call (RemoveProjectMember uses it to
// revoke stale per-secret grants when a member is removed, CWE-284) rather
// than an ordinary CRUD passthrough, so leaving it unsupported under
// storage.type: remote silently reintroduced the exact stale-grant exposure
// the call exists to close.
package store

import (
	"context"
	"fmt"

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

// DeleteSecretACLsByUserAndProject proxies to POST
// /api/v1/system/rbac/delete-secret-acls-by-user-and-project, mirroring
// ClearProjectSecretOwnership's identical passthrough pattern immediately
// above it at RemoveProjectMember's call site.
func (rs *RemoteStorage) DeleteSecretACLsByUserAndProject(ctx context.Context, userID, projectID uint) error {
	payload := map[string]uint{"user_id": userID, "project_id": projectID}
	resp, err := rs.client.Post(ctx, "/api/v1/system/rbac/delete-secret-acls-by-user-and-project", payload)
	if err != nil {
		return fmt.Errorf("failed to delete secret ACLs by user and project: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("delete secret ACLs by user and project failed: %s", resp.Error.Error())
	}
	return nil
}

// GetSecretAncestors is the folder-ACL inheritance walk helper. Folder-ACL
// enforcement is server-side only; the inheritance walk in HasSecretACL skips
// this path when ErrUnsupportedByBackend is returned.
func (rs *RemoteStorage) GetSecretAncestors(_ context.Context, _ uint) ([]uint, error) {
	return nil, remoteUnsupported("GetSecretAncestors")
}
