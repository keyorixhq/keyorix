// remote_invitations.go — invitations + access requests for RemoteStorage (ADR-024).
//
// Processed server-side in remote mode; stubs. For the local (GORM) equivalent
// see local_invitations.go.
package store

import (
	"context"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateProjectInvitation(_ context.Context, _ *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	return nil, remoteUnsupported("CreateProjectInvitation")
}

func (rs *RemoteStorage) GetProjectInvitation(_ context.Context, _ uint) (*models.ProjectInvitation, error) {
	return nil, remoteUnsupported("GetProjectInvitation")
}

func (rs *RemoteStorage) UpdateProjectInvitation(_ context.Context, _ *models.ProjectInvitation) (bool, error) {
	return false, remoteUnsupported("UpdateProjectInvitation")
}

func (rs *RemoteStorage) ListProjectInvitations(_ context.Context, _ uint) ([]*models.ProjectInvitation, error) {
	return nil, remoteUnsupported("ListProjectInvitations")
}

func (rs *RemoteStorage) CreateAccessRequest(_ context.Context, _ *models.AccessRequest) (*models.AccessRequest, error) {
	return nil, remoteUnsupported("CreateAccessRequest")
}

func (rs *RemoteStorage) GetAccessRequest(_ context.Context, _ uint) (*models.AccessRequest, error) {
	return nil, remoteUnsupported("GetAccessRequest")
}

func (rs *RemoteStorage) UpdateAccessRequest(_ context.Context, _ *models.AccessRequest) (bool, error) {
	return false, remoteUnsupported("UpdateAccessRequest")
}

func (rs *RemoteStorage) ListAccessRequests(_ context.Context, _ uint) ([]*models.AccessRequest, error) {
	return nil, remoteUnsupported("ListAccessRequests")
}

func (rs *RemoteStorage) CreateAccessRequestApproval(_ context.Context, _ *models.AccessRequestApproval) error {
	return remoteUnsupported("CreateAccessRequestApproval")
}

func (rs *RemoteStorage) ListAccessRequestApprovals(_ context.Context, _ uint) ([]*models.AccessRequestApproval, error) {
	return nil, remoteUnsupported("ListAccessRequestApprovals")
}
