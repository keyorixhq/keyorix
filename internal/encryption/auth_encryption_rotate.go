// auth_encryption_rotate.go — RotateAuthEncryption and per-type rotation helpers.
//
// RotateAuthEncryption, rotateAPIClientSecrets, rotateSessionTokens, rotateAPITokens.
// For encrypt/decrypt see auth_encryption.go. For DB store/retrieve see auth_encryption_store.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// RotateAuthEncryption re-encrypts all authentication data (API clients, sessions, API tokens).
func (ae *AuthEncryption) RotateAuthEncryption() error {
	if !ae.service.IsEnabled() {
		return fmt.Errorf("encryption is disabled")
	}
	if err := ae.rotateAPIClientSecrets(); err != nil {
		return fmt.Errorf("failed to rotate API client secrets: %w", err)
	}
	if err := ae.rotateSessionTokens(); err != nil {
		return fmt.Errorf("failed to rotate session tokens: %w", err)
	}
	if err := ae.rotateAPITokens(); err != nil {
		return fmt.Errorf("failed to rotate API tokens: %w", err)
	}
	return nil
}

func (ae *AuthEncryption) rotateAPIClientSecrets() error {
	var clients []models.APIClient
	if err := ae.db.Find(&clients).Error; err != nil {
		return fmt.Errorf("failed to retrieve API clients: %w", err)
	}
	for _, client := range clients {
		plain, err := ae.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt client secret for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptClientSecret(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt client secret: %w", err)
		}
		if err := ae.db.Model(&client).Updates(map[string]interface{}{
			"encrypted_client_secret": enc,
			"client_secret_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated client secret: %w", err)
		}
	}
	return nil
}

func (ae *AuthEncryption) rotateSessionTokens() error {
	var sessions []models.Session
	if err := ae.db.Find(&sessions).Error; err != nil {
		return fmt.Errorf("failed to retrieve sessions: %w", err)
	}
	for _, session := range sessions {
		plain, err := ae.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt session token for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptSessionToken(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt session token: %w", err)
		}
		if err := ae.db.Model(&session).Updates(map[string]interface{}{
			"encrypted_session_token": enc,
			"session_token_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated session token: %w", err)
		}
	}
	return nil
}

func (ae *AuthEncryption) rotateAPITokens() error {
	var tokens []models.APIToken
	if err := ae.db.Find(&tokens).Error; err != nil {
		return fmt.Errorf("failed to retrieve API tokens: %w", err)
	}
	for _, token := range tokens {
		plain, err := ae.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt API token for rotation: %w", err)
		}
		enc, meta, err := ae.EncryptAPIToken(plain)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt API token: %w", err)
		}
		if err := ae.db.Model(&token).Updates(map[string]interface{}{
			"encrypted_token": enc,
			"token_metadata":  models.JSON(meta),
		}).Error; err != nil {
			return fmt.Errorf("failed to update rotated API token: %w", err)
		}
	}
	return nil
}
