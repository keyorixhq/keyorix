// remote_usage.go — Per-project usage report stub for RemoteStorage.
//
// Usage report queries aggregate data from secret_nodes + audit_events, both
// of which live server-side. A future PR may add a /api/v1/admin/usage proxy
// route (mirroring the HTTP handler already wired on the server) so CLI users
// in remote mode can pull reports without a direct DB connection.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/core/storage"
)

// GetProjectUsageStats is not supported in remote mode; usage report queries
// run server-side against the live database.
func (rs *RemoteStorage) GetProjectUsageStats(_ context.Context, _ []uint, _ int) ([]storage.ProjectUsageStat, error) {
	return nil, remoteUnsupported("GetProjectUsageStats")
}
