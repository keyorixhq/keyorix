// remote_access_activity.go — dormant-access activity lookup for RemoteStorage.
// Computed server-side; stub here. See local_access_activity.go.
package store

import (
	"context"
	"time"
)

func (rs *RemoteStorage) LastUserSecretActivity(_ context.Context, _ uint) (map[uint]time.Time, error) {
	return nil, remoteUnsupported("LastUserSecretActivity")
}
