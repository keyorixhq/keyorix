// local_memberships.go — project membership lifecycle persistence (ADR-022).
//
// The ProjectMembership table tracks onboarding state, separate from the role
// grant in user_roles. For the remote (HTTP) equivalent see remote_memberships.go.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	if err := ls.db.WithContext(ctx).Create(m).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return m, nil
}

func (ls *LocalStorage) GetProjectMembership(ctx context.Context, id uint) (*models.ProjectMembership, error) {
	var m models.ProjectMembership
	if err := ls.db.WithContext(ctx).First(&m, id).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

func (ls *LocalStorage) UpdateProjectMembership(ctx context.Context, m *models.ProjectMembership) error {
	if err := ls.db.WithContext(ctx).Save(m).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

func (ls *LocalStorage) ListProjectMemberships(ctx context.Context, projectID uint) ([]*models.ProjectMembership, error) {
	var rows []*models.ProjectMembership
	err := ls.db.WithContext(ctx).
		Where("project_id = ?", projectID).
		Order("invited_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) GetActiveProjectMembership(ctx context.Context, projectID, userID uint) (*models.ProjectMembership, error) {
	var m models.ProjectMembership
	err := ls.db.WithContext(ctx).
		Where("project_id = ? AND user_id = ? AND state <> ?", projectID, userID, "revoked").
		First(&m).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorNotFound", nil), err)
	}
	return &m, nil
}

func (ls *LocalStorage) ListStaleInvitedMemberships(ctx context.Context, before time.Time) ([]*models.ProjectMembership, error) {
	var rows []*models.ProjectMembership
	err := ls.db.WithContext(ctx).
		Where("state = ? AND invited_at < ?", "invited", before).
		Order("invited_at ASC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) ListUserProjectMemberships(ctx context.Context, userID uint) ([]*models.ProjectMembership, error) {
	var rows []*models.ProjectMembership
	err := ls.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("invited_at DESC").
		Find(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	return rows, nil
}

func (ls *LocalStorage) CountProjectMembershipsByUsers(ctx context.Context, userIDs []uint) (map[uint]storage.MembershipCounts, error) {
	counts := make(map[uint]storage.MembershipCounts, len(userIDs))
	if len(userIDs) == 0 {
		return counts, nil
	}
	// One grouped query: per user, active = state 'active', total = non-revoked.
	// CASE/SUM keeps this valid on both SQLite (store tests) and Postgres.
	var rows []struct {
		UserID uint
		Active int
		Total  int
	}
	err := ls.db.WithContext(ctx).
		Model(&models.ProjectMembership{}).
		Select("user_id, "+
			"SUM(CASE WHEN state = 'active' THEN 1 ELSE 0 END) AS active, "+
			"SUM(CASE WHEN state <> 'revoked' THEN 1 ELSE 0 END) AS total").
		Where("user_id IN ?", userIDs).
		Group("user_id").
		Scan(&rows).Error
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	for _, r := range rows {
		counts[r.UserID] = storage.MembershipCounts{Active: r.Active, Total: r.Total}
	}
	return counts, nil
}
