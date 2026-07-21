// remote_read_quota.go — RemoteStorage stub for ListSecretsWithQuota.
//
// Read-quota scanning is a server-internal background job that always runs
// against the server's own LocalStorage — there is no self-scoped API route
// that exposes raw SecretNode rows (with MaxReads/ReadCount) to a remote
// client, so this path is deliberately unsupported on RemoteStorage.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListSecretsWithQuota is not supported in remote storage. The read-quota
// check runs server-side against LocalStorage only.
func (rs *RemoteStorage) ListSecretsWithQuota(_ context.Context) ([]models.SecretNode, error) {
	return nil, remoteUnsupported("ListSecretsWithQuota")
}
