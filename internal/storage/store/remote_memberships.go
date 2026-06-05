// remote_memberships.go — project membership lifecycle for RemoteStorage.
//
// Membership lifecycle is processed server-side in remote mode; these are stubs.
// For the local (GORM) equivalent see local_memberships.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (rs *RemoteStorage) CreateProjectMembership(_ context.Context, _ *models.ProjectMembership) (*models.ProjectMembership, error) {
	return nil, fmt.Errorf("CreateProjectMembership not implemented for remote storage")
}

func (rs *RemoteStorage) GetProjectMembership(_ context.Context, _ uint) (*models.ProjectMembership, error) {
	return nil, fmt.Errorf("GetProjectMembership not implemented for remote storage")
}

func (rs *RemoteStorage) UpdateProjectMembership(_ context.Context, _ *models.ProjectMembership) error {
	return fmt.Errorf("UpdateProjectMembership not implemented for remote storage")
}

func (rs *RemoteStorage) ListProjectMemberships(_ context.Context, _ uint) ([]*models.ProjectMembership, error) {
	return nil, fmt.Errorf("ListProjectMemberships not implemented for remote storage")
}

func (rs *RemoteStorage) GetActiveProjectMembership(_ context.Context, _, _ uint) (*models.ProjectMembership, error) {
	return nil, fmt.Errorf("GetActiveProjectMembership not implemented for remote storage")
}

func (rs *RemoteStorage) ListStaleInvitedMemberships(_ context.Context, _ time.Time) ([]*models.ProjectMembership, error) {
	return nil, fmt.Errorf("ListStaleInvitedMemberships not implemented for remote storage")
}
