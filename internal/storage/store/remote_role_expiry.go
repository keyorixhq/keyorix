// remote_role_expiry.go — RemoteStorage stub for ListExpiringUserRoles.
//
// Role-expiry scanning is a server-internal background job that always runs
// against the server's own LocalStorage — there is no self-scoped API route
// that exposes raw UserRole rows to a remote client, so this path is
// deliberately unsupported on RemoteStorage.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListExpiringUserRoles is not supported in remote storage. The role-expiry
// check runs server-side against LocalStorage only.
func (rs *RemoteStorage) ListExpiringUserRoles(_ context.Context, _ time.Time) ([]models.UserRole, error) {
	return nil, remoteUnsupported("ListExpiringUserRoles")
}
