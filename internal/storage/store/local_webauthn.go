// local_webauthn.go — WebAuthn / passkey persistence (ADR-036): registered
// credentials and the short-lived, single-use ceremony sessions.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func (ls *LocalStorage) CreateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	return ls.db.WithContext(ctx).Create(c).Error
}

func (ls *LocalStorage) ListWebAuthnCredentials(ctx context.Context, userID uint) ([]*models.WebAuthnCredential, error) {
	var creds []*models.WebAuthnCredential
	if err := ls.db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at").Find(&creds).Error; err != nil {
		return nil, err
	}
	return creds, nil
}

func (ls *LocalStorage) GetWebAuthnCredentialByCredID(ctx context.Context, credentialID []byte) (*models.WebAuthnCredential, error) {
	var c models.WebAuthnCredential
	if err := ls.db.WithContext(ctx).Where("credential_id = ?", credentialID).First(&c).Error; err != nil {
		return nil, err
	}
	return &c, nil
}

func (ls *LocalStorage) UpdateWebAuthnCredential(ctx context.Context, c *models.WebAuthnCredential) error {
	return ls.db.WithContext(ctx).Save(c).Error
}

// DeleteWebAuthnCredential removes one of the user's credentials (scoped by user
// so a caller can't delete another user's passkey by id).
func (ls *LocalStorage) DeleteWebAuthnCredential(ctx context.Context, userID, id uint) error {
	res := ls.db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&models.WebAuthnCredential{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return fmt.Errorf("credential not found")
	}
	return nil
}

func (ls *LocalStorage) CountWebAuthnCredentials(ctx context.Context, userID uint) (int64, error) {
	var n int64
	if err := ls.db.WithContext(ctx).Model(&models.WebAuthnCredential{}).
		Where("user_id = ?", userID).Count(&n).Error; err != nil {
		return 0, err
	}
	return n, nil
}

func (ls *LocalStorage) SetUserWebAuthnEnabled(ctx context.Context, userID uint, enabled bool) error {
	return ls.db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).Update("web_authn_enabled", enabled).Error
}

func (ls *LocalStorage) CreateWebAuthnSession(ctx context.Context, s *models.WebAuthnSession) error {
	return ls.db.WithContext(ctx).Create(s).Error
}

// ConsumeWebAuthnSession atomically marks a valid (unused, unexpired) ceremony
// session used and returns it. Returns an error if none matched.
func (ls *LocalStorage) ConsumeWebAuthnSession(ctx context.Context, tokenHash string, now time.Time) (*models.WebAuthnSession, error) {
	var sess *models.WebAuthnSession
	err := ls.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		res := tx.Model(&models.WebAuthnSession{}).
			Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, now).
			Update("used_at", now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return fmt.Errorf("invalid or expired webauthn session")
		}
		var loaded models.WebAuthnSession
		if err := tx.Where("token_hash = ?", tokenHash).First(&loaded).Error; err != nil {
			return err
		}
		sess = &loaded
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}
