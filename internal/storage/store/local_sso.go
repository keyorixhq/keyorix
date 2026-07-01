// local_sso.go — short-lived OIDC-login state (human SSO). See remote_sso.go for
// the server-side-only remote stubs.
package store

import (
	"context"
	"fmt"

	"gorm.io/gorm/clause"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	if err := ls.db.WithContext(ctx).Create(s).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ConsumeSSOLoginState atomically deletes the state row by its unique state token
// and returns the deleted row's data (RETURNING) — a single-statement claim, not a
// read-then-delete, so two concurrent callbacks racing the same state can never
// both succeed: only the DELETE that actually removes a row (RowsAffected==1) gets
// the data back, and the loser sees zero rows deleted (not-found). Returns the
// not-found error if the state is absent or already consumed.
func (ls *LocalStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	var s models.SSOLoginState
	result := ls.db.WithContext(ctx).Clauses(clause.Returning{}).Where("state = ?", state).Delete(&s)
	if result.Error != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), result.Error)
	}
	if result.RowsAffected == 0 {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return &s, nil
}
