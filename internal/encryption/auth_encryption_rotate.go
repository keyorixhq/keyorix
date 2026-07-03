// auth_encryption_rotate.go — RotateAuthEncryption and per-type rotation helpers.
//
// RotateAuthEncryption, rotateAPIClientSecrets, rotateSessionTokens, rotateAPITokens,
// rotatePasswordResetTokens.
// For encrypt/decrypt see auth_encryption.go. For DB store/retrieve see auth_encryption_store.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// RotateAuthEncryption re-encrypts all authentication data (API clients, sessions,
// API tokens, password reset tokens) with the current key.
//
// The whole sweep runs inside a single DB transaction — committed only if every
// row rotates cleanly, rolled back on any failure — mirroring the live
// RotateDEKWithSweep→SweepAllTables pattern (internal/encryption/service_rotation.go,
// sweep.go) so a mid-loop failure can never leave a permanent partial-rotation
// state (some rows under the new key, the rest stuck under the old one).
func (ae *AuthEncryption) RotateAuthEncryption() error {
	if !ae.service.IsEnabled() {
		return fmt.Errorf("encryption is disabled")
	}

	tx := ae.db.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin rotation transaction: %w", tx.Error)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	if err := ae.rotateAPIClientSecrets(tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to rotate API client secrets: %w", err)
	}
	if err := ae.rotateSessionTokens(tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to rotate session tokens: %w", err)
	}
	if err := ae.rotateAPITokens(tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to rotate API tokens: %w", err)
	}
	if err := ae.rotatePasswordResetTokens(tx); err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to rotate password reset tokens: %w", err)
	}

	if err := tx.Commit().Error; err != nil {
		return fmt.Errorf("failed to commit rotation transaction: %w", err)
	}
	return nil
}

func (ae *AuthEncryption) rotateAPIClientSecrets(tx *gorm.DB) error {
	var clients []models.APIClient
	if err := tx.Find(&clients).Error; err != nil {
		return fmt.Errorf("failed to retrieve API clients: %w", err)
	}
	for _, client := range clients {
		if len(client.EncryptedClientSecret) == 0 {
			// #278: row has no Encrypted* value yet (still plaintext-only, or never
			// populated) — nothing to rotate. Skip rather than abort the whole loop;
			// run 'auth-encryption migrate' first to bring it under encryption.
			continue
		}
		plain, err := ae.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt client secret for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptClientSecret(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt client secret: %w", err)
		}
		if err := tx.Model(&client).Updates(map[string]interface{}{
			"encrypted_client_secret": enc,
			"client_secret_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated client secret: %w", err)
		}
	}
	return nil
}

func (ae *AuthEncryption) rotateSessionTokens(tx *gorm.DB) error {
	var sessions []models.Session
	if err := tx.Find(&sessions).Error; err != nil {
		return fmt.Errorf("failed to retrieve sessions: %w", err)
	}
	for _, session := range sessions {
		if len(session.EncryptedSessionToken) == 0 {
			continue // #278: unmigrated row — nothing to rotate.
		}
		plain, err := ae.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt session token for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptSessionToken(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt session token: %w", err)
		}
		if err := tx.Model(&session).Updates(map[string]interface{}{
			"encrypted_session_token": enc,
			"session_token_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated session token: %w", err)
		}
	}
	return nil
}

func (ae *AuthEncryption) rotateAPITokens(tx *gorm.DB) error {
	var tokens []models.APIToken
	if err := tx.Find(&tokens).Error; err != nil {
		return fmt.Errorf("failed to retrieve API tokens: %w", err)
	}
	for _, token := range tokens {
		if len(token.EncryptedToken) == 0 {
			continue // #278: unmigrated row — nothing to rotate.
		}
		plain, err := ae.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt API token for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptAPIToken(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt API token: %w", err)
		}
		if err := tx.Model(&token).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated API token: %w", err)
		}
	}
	return nil
}

// rotatePasswordResetTokens re-encrypts password reset tokens. It was missing
// entirely despite RotateAuthEncryption's callers (the CLI Long help text, and
// AuthEncryptionCmd's own package doc) claiming to rotate "all" authentication
// data including password reset tokens (#292) — added here to match migrate's
// and validate's existing password-reset-token coverage rather than narrowing
// the documented claim.
func (ae *AuthEncryption) rotatePasswordResetTokens(tx *gorm.DB) error {
	var resets []models.PasswordReset
	if err := tx.Find(&resets).Error; err != nil {
		return fmt.Errorf("failed to retrieve password reset tokens: %w", err)
	}
	for _, reset := range resets {
		if len(reset.EncryptedToken) == 0 {
			continue // #278: unmigrated row — nothing to rotate.
		}
		plain, err := ae.DecryptPasswordResetToken(reset.EncryptedToken, []byte(reset.TokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt password reset token for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptPasswordResetToken(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt password reset token: %w", err)
		}
		if err := tx.Model(&reset).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated password reset token: %w", err)
		}
	}
	return nil
}
