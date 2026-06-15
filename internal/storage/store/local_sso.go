// local_sso.go — short-lived OIDC-login state (human SSO). See remote_sso.go for
// the server-side-only remote stubs.
package store

import (
	"context"
	"errors"
	"fmt"

	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func (ls *LocalStorage) CreateSSOLoginState(ctx context.Context, s *models.SSOLoginState) error {
	if err := ls.db.WithContext(ctx).Create(s).Error; err != nil {
		return fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return nil
}

// ConsumeSSOLoginState returns the state row and deletes it (single use), so a
// callback's state can never be replayed. Returns the not-found error if absent.
func (ls *LocalStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	var s models.SSOLoginState
	err := ls.db.WithContext(ctx).Where("state = ?", state).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	if err := ls.db.WithContext(ctx).Delete(&models.SSOLoginState{}, s.ID).Error; err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), err)
	}
	return &s, nil
}
