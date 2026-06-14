// local_invitations.go — project invitations + access requests persistence (ADR-024).
//
// For the remote (HTTP) equivalent see remote_invitations.go.
package store

import (
	"context"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// --- Project invitations ---

func (ls *LocalStorage) CreateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) (*models.ProjectInvitation, error) {
	if err := ls.db.WithContext(ctx).Create(inv).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return inv, nil
}

func (ls *LocalStorage) GetProjectInvitation(ctx context.Context, id uint) (*models.ProjectInvitation, error) {
	var inv models.ProjectInvitation
	if err := ls.db.WithContext(ctx).First(&inv, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &inv, nil
}

func (ls *LocalStorage) UpdateProjectInvitation(ctx context.Context, inv *models.ProjectInvitation) error {
	if err := ls.db.WithContext(ctx).Save(inv).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListProjectInvitations(ctx context.Context, projectID uint) ([]*models.ProjectInvitation, error) {
	var rows []*models.ProjectInvitation
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

// --- Access requests ---

func (ls *LocalStorage) CreateAccessRequest(ctx context.Context, req *models.AccessRequest) (*models.AccessRequest, error) {
	if err := ls.db.WithContext(ctx).Create(req).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return req, nil
}

func (ls *LocalStorage) GetAccessRequest(ctx context.Context, id uint) (*models.AccessRequest, error) {
	var req models.AccessRequest
	if err := ls.db.WithContext(ctx).First(&req, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &req, nil
}

func (ls *LocalStorage) UpdateAccessRequest(ctx context.Context, req *models.AccessRequest) error {
	if err := ls.db.WithContext(ctx).Save(req).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListAccessRequests(ctx context.Context, projectID uint) ([]*models.AccessRequest, error) {
	var rows []*models.AccessRequest
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("created_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CreateAccessRequestApproval(ctx context.Context, a *models.AccessRequestApproval) error {
	if err := ls.db.WithContext(ctx).Create(a).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListAccessRequestApprovals(ctx context.Context, requestID uint) ([]*models.AccessRequestApproval, error) {
	var rows []*models.AccessRequestApproval
	err := ls.db.WithContext(ctx).
		Where("request_id = ?", requestID).
		Order("id ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}
