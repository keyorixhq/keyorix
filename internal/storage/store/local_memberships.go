// local_memberships.go — project membership lifecycle persistence (ADR-022).
//
// The ProjectMembership table tracks onboarding state, separate from the role
// grant in user_roles. For the remote (HTTP) equivalent see remote_memberships.go.
package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/keyorixhq/keyorix/internal/core/storage"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateProjectMembership(ctx context.Context, m *models.ProjectMembership) (*models.ProjectMembership, error) {
	if err := ls.db.WithContext(ctx).Create(m).Error; err != nil {
		if isUniqueViolation(err) {
			// The partial unique index uniq_project_memberships_active (#309) caught a
			// concurrent duplicate: another invite for the same (project, user) committed
			// first. Translate to the sentinel so callers (InviteMember) can surface the
			// same clean "already has a membership" error a sequential caller would get,
			// instead of a raw constraint-violation message.
			return nil, fmt.Errorf("%w: %v", storage.ErrDuplicateActiveMembership, err)
		}
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return m, nil
}

// isUniqueViolation reports whether err looks like a unique-constraint violation from
// either backing DB driver. Neither SQLite's nor Postgres's default GORM dialector
// wraps a typed error here (that needs the gorm.Config{TranslateError: true} opt-in,
// which this codebase doesn't set), so this matches the driver-native message text —
// the same approach already used for "not found" detection elsewhere (e.g. sso.go,
// users.go, scim.go).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") || // SQLite
		strings.Contains(msg, "duplicate key value violates unique constraint") // Postgres
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

// TransitionProjectMembershipState persists m's full row via a conditional
// UPDATE gated on the row's CURRENT state still being fromState (#G42).
// Mirrors TransitionMachineIdentityState's `WHERE id = ? AND state = ?` +
// `Select("*")` shape exactly, so every field the caller mutated on m (State,
// UpdatedAt, ActivatedAt, RevokedAt, ...) is persisted in the same statement.
func (ls *LocalStorage) TransitionProjectMembershipState(ctx context.Context, m *models.ProjectMembership, fromState string) (bool, error) {
	res := ls.db.WithContext(ctx).Model(&models.ProjectMembership{}).
		Where("id = ? AND state = ?", m.ID, fromState).
		Select("*").
		Updates(m)
	if res.Error != nil {
		return false, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	return res.RowsAffected == 1, nil
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
		Limit(maxUnboundedListRows).
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
