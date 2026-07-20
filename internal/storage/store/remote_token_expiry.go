// remote_token_expiry.go — RemoteStorage stubs for ListExpiringPATs and
// ListExpiringMachineCredentials.
//
// Token-expiry scanning is a server-internal background job that always runs
// against the server's own LocalStorage — there is no self-scoped API route
// that exposes raw PAT or credential rows to a remote client, so these paths
// are deliberately unsupported on RemoteStorage.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListExpiringPATs is not supported in remote storage. The token-expiry
// check runs server-side against LocalStorage only.
func (rs *RemoteStorage) ListExpiringPATs(_ context.Context, _ time.Time) ([]models.PersonalAccessToken, error) {
	return nil, remoteUnsupported("ListExpiringPATs")
}

// ListExpiringMachineCredentials is not supported in remote storage. The
// token-expiry check runs server-side against LocalStorage only.
func (rs *RemoteStorage) ListExpiringMachineCredentials(_ context.Context, _ time.Time) ([]models.MachineIdentityCredential, error) {
	return nil, remoteUnsupported("ListExpiringMachineCredentials")
}
