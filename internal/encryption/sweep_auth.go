// sweep_auth.go — Re-encryption sweep for auth tables (sessions, API tokens, clients, password resets).
//
// These four sweepers follow an identical pattern: fetch all rows, decrypt with
// oldSvc, re-encrypt with newSvc, write back. No AAD required (auth tokens are
// not AAD-bound). See sweep.go for the AAD-aware secret_versions sweep.
package encryption

import (
	"encoding/json"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

func sweepSessions(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var sessions []models.Session
	if err := tx.Find(&sessions).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch sessions: %w", err)
	}
	swept := 0
	for _, session := range sessions {
		if len(session.EncryptedSessionToken) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(session.EncryptedSessionToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize session id=%d: %w", session.ID, err)
		}
		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt session id=%d: %w", session.ID, err)
		}
		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt session id=%d: %w", session.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize session id=%d: %w", session.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal session metadata id=%d: %w", session.ID, err)
		}
		if err := tx.Model(&models.Session{}).Where("id = ?", session.ID).Updates(map[string]interface{}{
			"encrypted_session_token": newBytes,
			"session_token_metadata":  models.JSON(metaBytes),
		}).Error; err != nil {
			return swept, fmt.Errorf("failed to update session id=%d: %w", session.ID, err)
		}
		swept++
	}
	return swept, nil
}

func sweepAPITokens(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var tokens []models.APIToken
	if err := tx.Find(&tokens).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch api_tokens: %w", err)
	}
	swept := 0
	for _, token := range tokens {
		if len(token.EncryptedToken) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(token.EncryptedToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize api_token id=%d: %w", token.ID, err)
		}
		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt api_token id=%d: %w", token.ID, err)
		}
		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt api_token id=%d: %w", token.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize api_token id=%d: %w", token.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal api_token metadata id=%d: %w", token.ID, err)
		}
		if err := tx.Model(&models.APIToken{}).Where("id = ?", token.ID).Updates(map[string]interface{}{
			"encrypted_token": newBytes,
			"token_metadata":  models.JSON(metaBytes),
		}).Error; err != nil {
			return swept, fmt.Errorf("failed to update api_token id=%d: %w", token.ID, err)
		}
		swept++
	}
	return swept, nil
}

func sweepAPIClients(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var clients []models.APIClient
	if err := tx.Find(&clients).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch api_clients: %w", err)
	}
	swept := 0
	for _, client := range clients {
		if len(client.EncryptedClientSecret) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(client.EncryptedClientSecret)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize api_client id=%d: %w", client.ID, err)
		}
		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt api_client id=%d: %w", client.ID, err)
		}
		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt api_client id=%d: %w", client.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize api_client id=%d: %w", client.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal api_client metadata id=%d: %w", client.ID, err)
		}
		if err := tx.Model(&models.APIClient{}).Where("id = ?", client.ID).Updates(map[string]interface{}{
			"encrypted_client_secret": newBytes,
			"client_secret_metadata":  models.JSON(metaBytes),
		}).Error; err != nil {
			return swept, fmt.Errorf("failed to update api_client id=%d: %w", client.ID, err)
		}
		swept++
	}
	return swept, nil
}

func sweepPasswordResets(tx *gorm.DB, oldSvc *EncryptionService, newSvc *EncryptionService, newKeyVersion string) (int, error) {
	var resets []models.PasswordReset
	if err := tx.Find(&resets).Error; err != nil {
		return 0, fmt.Errorf("failed to fetch password_resets: %w", err)
	}
	swept := 0
	for _, reset := range resets {
		if len(reset.EncryptedToken) == 0 {
			continue
		}
		encrypted, err := DeserializeEncryptedData(reset.EncryptedToken)
		if err != nil {
			return swept, fmt.Errorf("failed to deserialize password_reset id=%d: %w", reset.ID, err)
		}
		plaintext, err := oldSvc.Decrypt(encrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to decrypt password_reset id=%d: %w", reset.ID, err)
		}
		newEncrypted, err := newSvc.Encrypt(plaintext, newKeyVersion)
		wipeBytes(plaintext)
		if err != nil {
			return swept, fmt.Errorf("failed to re-encrypt password_reset id=%d: %w", reset.ID, err)
		}
		newBytes, err := SerializeEncryptedData(newEncrypted)
		if err != nil {
			return swept, fmt.Errorf("failed to serialize password_reset id=%d: %w", reset.ID, err)
		}
		metaBytes, err := json.Marshal(newEncrypted.Metadata)
		if err != nil {
			return swept, fmt.Errorf("failed to marshal password_reset metadata id=%d: %w", reset.ID, err)
		}
		if err := tx.Model(&models.PasswordReset{}).Where("id = ?", reset.ID).Updates(map[string]interface{}{
			"encrypted_token": newBytes,
			"token_metadata":  models.JSON(metaBytes),
		}).Error; err != nil {
			return swept, fmt.Errorf("failed to update password_reset id=%d: %w", reset.ID, err)
		}
		swept++
	}
	return swept, nil
}
