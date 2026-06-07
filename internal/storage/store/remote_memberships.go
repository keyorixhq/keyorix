// remote_memberships.go — project membership lifecycle for RemoteStorage.
//
// Membership lifecycle is processed server-side in remote mode; these are stubs.
// For the local (GORM) equivalent see local_memberships.go.
package store

import (
	"context"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateProjectMembership(_ context.Context, _ *models.ProjectMembership) (*models.ProjectMembership, error) {
	return nil, remoteUnsupported("CreateProjectMembership")
}

func (rs *RemoteStorage) GetProjectMembership(_ context.Context, _ uint) (*models.ProjectMembership, error) {
	return nil, remoteUnsupported("GetProjectMembership")
}

func (rs *RemoteStorage) UpdateProjectMembership(_ context.Context, _ *models.ProjectMembership) error {
	return remoteUnsupported("UpdateProjectMembership")
}

func (rs *RemoteStorage) ListProjectMemberships(_ context.Context, _ uint) ([]*models.ProjectMembership, error) {
	return nil, remoteUnsupported("ListProjectMemberships")
}

func (rs *RemoteStorage) GetActiveProjectMembership(_ context.Context, _, _ uint) (*models.ProjectMembership, error) {
	return nil, remoteUnsupported("GetActiveProjectMembership")
}

func (rs *RemoteStorage) ListStaleInvitedMemberships(_ context.Context, _ time.Time) ([]*models.ProjectMembership, error) {
	return nil, remoteUnsupported("ListStaleInvitedMemberships")
}

func (rs *RemoteStorage) ListUserProjectMemberships(_ context.Context, _ uint) ([]*models.ProjectMembership, error) {
	return nil, remoteUnsupported("ListUserProjectMemberships")
}

func (rs *RemoteStorage) CountProjectMembershipsByUsers(_ context.Context, _ []uint) (map[uint]storage.MembershipCounts, error) {
	return nil, remoteUnsupported("CountProjectMembershipsByUsers")
}
