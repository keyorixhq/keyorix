// remote_inactivity_suspend.go — RemoteStorage stub for ListInactiveUsers.
// The inactivity auto-suspension job (POST /api/v1/admin/jobs/suspend-inactive-users)
// runs entirely server-side; the CLI trigger POSTs to the HTTP endpoint via
// common.RemoteClient.Post rather than calling this storage method directly.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ListInactiveUsers is intentionally unsupported on RemoteStorage: the
// inactivity-suspension job runs server-side and its CLI entry-point calls
// the HTTP endpoint (POST /api/v1/admin/jobs/suspend-inactive-users) rather
// than this raw storage method.
func (rs *RemoteStorage) ListInactiveUsers(_ context.Context, _ time.Time) ([]*models.User, error) {
	return nil, remoteUnsupported("ListInactiveUsers")
}
