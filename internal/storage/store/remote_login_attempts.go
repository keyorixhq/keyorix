package store

import (
	"context"
	"time"
)

// Login rate limiting is server-side only (ADR-040) — the limiter runs in the
// server's auth handlers against LocalStorage; a remote (client) caller never
// records or counts attempts.
func (rs *RemoteStorage) RecordLoginAttempt(_ context.Context, _ string, _ time.Time) error {
	return remoteUnsupported("RecordLoginAttempt")
}
func (rs *RemoteStorage) CountRecentLoginAttempts(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("CountRecentLoginAttempts")
}
func (rs *RemoteStorage) PruneLoginAttempts(_ context.Context, _ time.Time) (int64, error) {
	return 0, remoteUnsupported("PruneLoginAttempts")
}
