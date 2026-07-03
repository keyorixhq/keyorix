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
//
// The delete itself — not the preceding read — is what makes this single-use: two
// concurrent callers can both pass the initial First() before either deletes (a plain
// read can't be the guard), so the DELETE is scoped with the same "id = ? AND state =
// ?" predicate the row was read with and RowsAffected is checked. Only the caller whose
// DELETE actually matched a row (RowsAffected == 1) gets to proceed; the DB itself
// (row-level lock on UPDATE/DELETE, re-evaluated after acquiring it, on every gorm
// driver this project supports) guarantees at most one concurrent DELETE against the
// same row can ever affect it — the same conditional-write pattern used elsewhere in
// this campaign (e.g. TryIncrementSecretReadCount, UpdateAccessReviewItem).
func (ls *LocalStorage) ConsumeSSOLoginState(ctx context.Context, state string) (*models.SSOLoginState, error) {
	var s models.SSOLoginState
	err := ls.db.WithContext(ctx).Where("state = ?", state).First(&s).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorRetrievalFailed", nil), err)
	}
	res := ls.db.WithContext(ctx).Where("id = ? AND state = ?", s.ID, state).Delete(&models.SSOLoginState{})
	if res.Error != nil {
		return nil, fmt.Errorf("%s: %w", i18n.T("ErrorStorageFailed", nil), res.Error)
	}
	if res.RowsAffected != 1 {
		// Lost the race: another caller's concurrent DELETE already consumed this
		// state. Report it exactly like an unknown/already-used state, not a
		// distinct error — that distinction isn't observable to a legitimate caller
		// and shouldn't be to a replaying one either.
		return nil, fmt.Errorf("%s", i18n.T("ErrorNotFound", nil))
	}
	return &s, nil
}
