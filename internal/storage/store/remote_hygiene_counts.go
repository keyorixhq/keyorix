// remote_hygiene_counts.go — credential-hygiene trend count stubs for RemoteStorage.
//
// Hygiene trend snapshots are written and read server-side only (the
// RecordHygieneTrendPoint job and GetHygieneTrends run on the server); no REST
// proxy routes exist for these raw storage calls. The count methods likewise run
// server-side as part of RecordHygieneTrendPoint. All are intentional stubs
// (statusIntentional in remote_hygiene_counts_completeness_test.go).
//
// For the local (GORM) equivalent see local_hygiene_counts.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SaveHygieneTrendSnapshot is not supported in remote mode.
func (rs *RemoteStorage) SaveHygieneTrendSnapshot(_ context.Context, _ *models.HygieneTrendSnapshot) error {
	return remoteUnsupported("SaveHygieneTrendSnapshot")
}

// ListHygieneTrendSnapshots is not supported in remote mode.
func (rs *RemoteStorage) ListHygieneTrendSnapshots(_ context.Context, _ int) ([]*models.HygieneTrendSnapshot, error) {
	return nil, remoteUnsupported("ListHygieneTrendSnapshots")
}

// CountStalePATs is not supported in remote mode.
func (rs *RemoteStorage) CountStalePATs(_ context.Context, _ time.Time) (int, error) {
	return 0, remoteUnsupported("CountStalePATs")
}

// CountExpiredPATs is not supported in remote mode.
func (rs *RemoteStorage) CountExpiredPATs(_ context.Context) (int, error) {
	return 0, remoteUnsupported("CountExpiredPATs")
}

// CountStaleMachineCredentials is not supported in remote mode.
func (rs *RemoteStorage) CountStaleMachineCredentials(_ context.Context, _ time.Time) (int, error) {
	return 0, remoteUnsupported("CountStaleMachineCredentials")
}
