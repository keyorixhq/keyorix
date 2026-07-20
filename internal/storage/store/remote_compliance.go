// remote_compliance.go — CompliancePostureSnapshot stubs for RemoteStorage.
//
// Compliance posture snapshots are written and read server-side only; no REST
// proxy routes exist for these operations, and no remote (CLI-side) caller ever
// invokes them directly — GetCompliancePosture is a server-side admin endpoint.
// Both methods are intentional stubs (statusIntentional in
// remote_unsupported_completeness_test.go).
//
// For the local (GORM) equivalent see local_compliance_snapshot.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// SaveCompliancePostureSnapshot is a no-op in remote mode — compliance posture
// snapshots are managed server-side.
func (rs *RemoteStorage) SaveCompliancePostureSnapshot(_ context.Context, _ *models.CompliancePostureSnapshot) error {
	return remoteUnsupported("SaveCompliancePostureSnapshot")
}

// GetPreviousCompliancePostureSnapshot is not supported in remote mode.
func (rs *RemoteStorage) GetPreviousCompliancePostureSnapshot(_ context.Context, _ time.Time) (*models.CompliancePostureSnapshot, error) {
	return nil, remoteUnsupported("GetPreviousCompliancePostureSnapshot")
}
