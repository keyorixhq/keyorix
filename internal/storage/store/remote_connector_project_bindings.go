// remote_connector_project_bindings.go — RemoteStorage stubs for Connect
// connector→project ID bindings (ADR-082 branch 2).
//
// #1480: GetConnectorProjectBinding/CreateConnectorProjectBinding used to be
// real, DB-backed HTTP implementations, kept live specifically to avoid a
// #527-shaped boot failure for a "downstream Keyorix server" proxying these
// to an upstream. That topology cannot exist (ADR-083:
// validateRemoteStorageNotServer rejects storage.type: remote for any server
// process). Their only real caller, repo-wide, was server/main.go's
// resolveConnectorOwnership at boot time — which calls storage.Storage
// methods directly against coreService.Storage(), i.e. whatever backend the
// running server was actually configured with, which can never be
// RemoteStorage. No internal/core method reaches either one, so no CLI
// command under storage.type: remote could reach them either. Converted to
// stubs alongside their now-dead /system routes
// (GetConnectorProjectBindingProxy/CreateConnectorProjectBindingProxy,
// server/http/handlers/connector_project_bindings_proxy.go) — same reasoning
// ListConnectorProjectBindings below already used.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// GetConnectorProjectBinding is not supported in remote storage — see the
// package doc above.
func (rs *RemoteStorage) GetConnectorProjectBinding(_ context.Context, _ string) (*models.ConnectorProjectBinding, error) {
	return nil, remoteUnsupported("GetConnectorProjectBinding")
}

// ListConnectorProjectBindings is not supported in remote storage: it backs
// only the boot-time orphan-detection warning (server/main.go), a diagnostic
// that runs against the resolving server's OWN storage — the same "a server
// on storage.type: remote never reaches this code" reasoning ADR-083
// established for the RBAC primitives this mirrors (see remote_rbac.go),
// not the #527 "would fail boot" failure shape Get/CreateConnectorProjectBinding
// above are real implementations to avoid.
func (rs *RemoteStorage) ListConnectorProjectBindings(_ context.Context) ([]*models.ConnectorProjectBinding, error) {
	return nil, remoteUnsupported("ListConnectorProjectBindings")
}

// CreateConnectorProjectBinding is not supported in remote storage — see the
// package doc above.
func (rs *RemoteStorage) CreateConnectorProjectBinding(_ context.Context, _ *models.ConnectorProjectBinding) (*models.ConnectorProjectBinding, error) {
	return nil, remoteUnsupported("CreateConnectorProjectBinding")
}
