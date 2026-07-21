// remote_bulk_access.go — RemoteStorage stubs for rejection-reason template
// management and the bulk access-request ID lookup. The REST API endpoints
// (/api/v1/rejection-reason-templates, /api/v1/access-requests/bulk-approve,
// /api/v1/access-requests/bulk-reject) are the remote surface; these methods
// are never invoked directly by a remote-storage caller. All four are
// intentional stubs documented in remote_unsupported_completeness_test.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateRejectionReasonTemplate(_ context.Context, _ *models.RejectionReasonTemplate) error {
	return remoteUnsupported("CreateRejectionReasonTemplate")
}

func (rs *RemoteStorage) ListRejectionReasonTemplates(_ context.Context) ([]models.RejectionReasonTemplate, error) {
	return nil, remoteUnsupported("ListRejectionReasonTemplates")
}

func (rs *RemoteStorage) DeleteRejectionReasonTemplate(_ context.Context, _ uint) error {
	return remoteUnsupported("DeleteRejectionReasonTemplate")
}

func (rs *RemoteStorage) ListAccessRequestsByIDs(_ context.Context, _ []uint) ([]*models.AccessRequest, error) {
	return nil, remoteUnsupported("ListAccessRequestsByIDs")
}
