// remote_retention_override.go — RemoteStorage stub for SetRetentionOverride.
//
// Per-secret retention override management is always server-side: the
// PATCH /api/v1/secrets/{id}/retention endpoint mutates the SecretNode row
// directly on the server. A remote client (storage.type: remote) never calls
// SetRetentionOverride on its own storage backend — it issues the HTTP request
// instead, and the server-side handler invokes LocalStorage. This stub is
// therefore intentionally permanent.
package store

import "context"

// SetRetentionOverride is not supported in remote storage. Override management
// is always performed server-side via PATCH /api/v1/secrets/{id}/retention.
func (rs *RemoteStorage) SetRetentionOverride(_ context.Context, _ uint, _ int) error {
	return remoteUnsupported("SetRetentionOverride")
}
