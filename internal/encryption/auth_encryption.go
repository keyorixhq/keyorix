// auth_encryption.go — AuthEncryption struct, constructor, and per-token-type encrypt/decrypt.
//
// Thin typed wrappers over Service.EncryptSecret/DecryptSecret for each auth token category.
// For DB store/retrieve operations see auth_encryption_store.go.
// For rotation see auth_encryption_rotate.go.
package encryption

import (
	"crypto/subtle"
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"gorm.io/gorm"
)

// AuthEncryption handles encryption for authentication-related data.
type AuthEncryption struct {
	service *Service
	db      *gorm.DB
}

// NewAuthEncryption creates a new AuthEncryption handler.
func NewAuthEncryption(cfg *config.EncryptionConfig, baseDir string, db *gorm.DB) *AuthEncryption {
	return &AuthEncryption{
		service: NewService(cfg, baseDir),
		db:      db,
	}
}

// Initialize initialises the underlying encryption service.
// passphrase is forwarded to the key manager for KEK derivation — never stored.
func (ae *AuthEncryption) Initialize(passphrase string) error {
	if !ae.service.IsEnabled() {
		return nil
	}
	return ae.service.Initialize(passphrase)
}

// GetAuthEncryptionStatus returns the current authentication encryption status.
func (ae *AuthEncryption) GetAuthEncryptionStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":     ae.service.IsEnabled(),
		"initialized": ae.service.IsInitialized(),
	}
	if ae.service.IsInitialized() {
		status["key_version"] = ae.service.GetKeyVersion()
	}
	return status
}

// ValidateEncryptedToken decrypts storedToken and compares to plainToken using constant-time compare.
func (ae *AuthEncryption) ValidateEncryptedToken(encryptedToken []byte, metadata []byte, plainToken string) (bool, error) {
	storedToken, err := ae.DecryptSessionToken(encryptedToken, metadata)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt stored token: %w", err)
	}
	return subtle.ConstantTimeCompare([]byte(storedToken), []byte(plainToken)) == 1, nil
}

// EncryptClientSecret encrypts an API client secret.
func (ae *AuthEncryption) EncryptClientSecret(plainSecret string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainSecret), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecret([]byte(plainSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}
	return enc, meta, nil
}

// DecryptClientSecret decrypts an API client secret.
func (ae *AuthEncryption) DecryptClientSecret(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	return string(plain), nil
}

// EncryptSessionToken encrypts a session token.
func (ae *AuthEncryption) EncryptSessionToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainToken), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt session token: %w", err)
	}
	return enc, meta, nil
}

// DecryptSessionToken decrypts a session token.
func (ae *AuthEncryption) DecryptSessionToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt session token: %w", err)
	}
	return string(plain), nil
}

// EncryptAPIToken encrypts an API token.
func (ae *AuthEncryption) EncryptAPIToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainToken), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt API token: %w", err)
	}
	return enc, meta, nil
}

// DecryptAPIToken decrypts an API token.
func (ae *AuthEncryption) DecryptAPIToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API token: %w", err)
	}
	return string(plain), nil
}

// EncryptPasswordResetToken encrypts a password reset token.
func (ae *AuthEncryption) EncryptPasswordResetToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		return []byte(plainToken), nil, nil
	}
	enc, meta, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt password reset token: %w", err)
	}
	return enc, meta, nil
}

// DecryptPasswordResetToken decrypts a password reset token.
func (ae *AuthEncryption) DecryptPasswordResetToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		return string(encryptedData), nil
	}
	plain, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password reset token: %w", err)
	}
	return string(plain), nil
}
