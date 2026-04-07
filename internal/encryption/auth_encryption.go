package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

// AuthEncryption handles encryption operations for authentication-related data
type AuthEncryption struct {
	service *Service
	db      *gorm.DB
}

// NewAuthEncryption creates a new authentication encryption handler
func NewAuthEncryption(cfg *config.EncryptionConfig, baseDir string, db *gorm.DB) *AuthEncryption {
	return &AuthEncryption{
		service: NewService(cfg, baseDir),
		db:      db,
	}
}

// Initialize initializes the authentication encryption service
func (ae *AuthEncryption) Initialize() error {
	if !ae.service.IsEnabled() {
		return nil // Encryption disabled, skip initialization
	}
	return ae.service.Initialize()
}

// EncryptClientSecret encrypts an API client secret
func (ae *AuthEncryption) EncryptClientSecret(plainSecret string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		// Return plaintext if encryption is disabled
		return []byte(plainSecret), nil, nil
	}

	// Encrypt the client secret
	encryptedData, metadata, err := ae.service.EncryptSecret([]byte(plainSecret))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	return encryptedData, metadata, nil
}

// DecryptClientSecret decrypts an API client secret
func (ae *AuthEncryption) DecryptClientSecret(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		// Return as-is if encryption is disabled
		return string(encryptedData), nil
	}

	// Decrypt the client secret
	plaintext, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	return string(plaintext), nil
}

// EncryptSessionToken encrypts a session token
func (ae *AuthEncryption) EncryptSessionToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		// Return plaintext if encryption is disabled
		return []byte(plainToken), nil, nil
	}

	// Encrypt the session token
	encryptedData, metadata, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt session token: %w", err)
	}

	return encryptedData, metadata, nil
}

// DecryptSessionToken decrypts a session token
func (ae *AuthEncryption) DecryptSessionToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		// Return as-is if encryption is disabled
		return string(encryptedData), nil
	}

	// Decrypt the session token
	plaintext, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt session token: %w", err)
	}

	return string(plaintext), nil
}

// EncryptAPIToken encrypts an API token
func (ae *AuthEncryption) EncryptAPIToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		// Return plaintext if encryption is disabled
		return []byte(plainToken), nil, nil
	}

	// Encrypt the API token
	encryptedData, metadata, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt API token: %w", err)
	}

	return encryptedData, metadata, nil
}

// DecryptAPIToken decrypts an API token
func (ae *AuthEncryption) DecryptAPIToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		// Return as-is if encryption is disabled
		return string(encryptedData), nil
	}

	// Decrypt the API token
	plaintext, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API token: %w", err)
	}

	return string(plaintext), nil
}

// EncryptPasswordResetToken encrypts a password reset token
func (ae *AuthEncryption) EncryptPasswordResetToken(plainToken string) ([]byte, []byte, error) {
	if !ae.service.IsEnabled() {
		// Return plaintext if encryption is disabled
		return []byte(plainToken), nil, nil
	}

	// Encrypt the password reset token
	encryptedData, metadata, err := ae.service.EncryptSecret([]byte(plainToken))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt password reset token: %w", err)
	}

	return encryptedData, metadata, nil
}

// DecryptPasswordResetToken decrypts a password reset token
func (ae *AuthEncryption) DecryptPasswordResetToken(encryptedData []byte, metadata []byte) (string, error) {
	if !ae.service.IsEnabled() {
		// Return as-is if encryption is disabled
		return string(encryptedData), nil
	}

	// Decrypt the password reset token
	plaintext, err := ae.service.DecryptSecret(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt password reset token: %w", err)
	}

	return string(plaintext), nil
}

// StoreEncryptedAPIClient creates an API client with encrypted secret
func (ae *AuthEncryption) StoreEncryptedAPIClient(client *models.APIClient, plainSecret string) error {
	// Encrypt the client secret
	encryptedSecret, metadata, err := ae.EncryptClientSecret(plainSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}

	// Update the client with encrypted data
	client.EncryptedClientSecret = encryptedSecret
	if metadata != nil {
		client.ClientSecretMetadata = datatypes.JSON(metadata)
	}

	// Store in database
	if err := ae.db.Create(client).Error; err != nil {
		return fmt.Errorf("failed to store API client: %w", err)
	}

	return nil
}

// RetrieveAPIClientSecret retrieves and decrypts an API client secret
func (ae *AuthEncryption) RetrieveAPIClientSecret(clientID string) (string, error) {
	var client models.APIClient
	if err := ae.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve API client: %w", err)
	}

	// Decrypt the client secret
	plainSecret, err := ae.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}

	return plainSecret, nil
}

// StoreEncryptedSession creates a session with encrypted token
func (ae *AuthEncryption) StoreEncryptedSession(session *models.Session, plainToken string) error {
	// Encrypt the session token
	encryptedToken, metadata, err := ae.EncryptSessionToken(plainToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt session token: %w", err)
	}

	// Update the session with encrypted data
	session.EncryptedSessionToken = encryptedToken
	if metadata != nil {
		session.SessionTokenMetadata = datatypes.JSON(metadata)
	}

	// Store in database
	if err := ae.db.Create(session).Error; err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}

	return nil
}

// RetrieveSessionToken retrieves and decrypts a session token
func (ae *AuthEncryption) RetrieveSessionToken(sessionID uint) (string, error) {
	var session models.Session
	if err := ae.db.First(&session, sessionID).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve session: %w", err)
	}

	// Decrypt the session token
	plainToken, err := ae.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt session token: %w", err)
	}

	return plainToken, nil
}

// StoreEncryptedAPIToken creates an API token with encrypted token
func (ae *AuthEncryption) StoreEncryptedAPIToken(token *models.APIToken, plainToken string) error {
	// Encrypt the API token
	encryptedToken, metadata, err := ae.EncryptAPIToken(plainToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt API token: %w", err)
	}

	// Update the token with encrypted data
	token.EncryptedToken = encryptedToken
	if metadata != nil {
		token.TokenMetadata = datatypes.JSON(metadata)
	}

	// Store in database
	if err := ae.db.Create(token).Error; err != nil {
		return fmt.Errorf("failed to store API token: %w", err)
	}

	return nil
}

// RetrieveAPIToken retrieves and decrypts an API token
func (ae *AuthEncryption) RetrieveAPIToken(tokenID uint) (string, error) {
	var token models.APIToken
	if err := ae.db.First(&token, tokenID).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve API token: %w", err)
	}

	// Decrypt the API token
	plainToken, err := ae.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API token: %w", err)
	}

	return plainToken, nil
}

// ValidateEncryptedToken validates an encrypted token against a plaintext token
func (ae *AuthEncryption) ValidateEncryptedToken(encryptedToken []byte, metadata []byte, plainToken string) (bool, error) {
	// Decrypt the stored token
	storedToken, err := ae.DecryptSessionToken(encryptedToken, metadata)
	if err != nil {
		return false, fmt.Errorf("failed to decrypt stored token: %w", err)
	}

	// Compare tokens
	return storedToken == plainToken, nil
}

// RotateAuthEncryption re-encrypts authentication data with new keys
func (ae *AuthEncryption) RotateAuthEncryption() error {
	if !ae.service.IsEnabled() {
		return fmt.Errorf("encryption is disabled")
	}

	// Rotate API client secrets
	if err := ae.rotateAPIClientSecrets(); err != nil {
		return fmt.Errorf("failed to rotate API client secrets: %w", err)
	}

	// Rotate session tokens
	if err := ae.rotateSessionTokens(); err != nil {
		return fmt.Errorf("failed to rotate session tokens: %w", err)
	}

	// Rotate API tokens
	if err := ae.rotateAPITokens(); err != nil {
		return fmt.Errorf("failed to rotate API tokens: %w", err)
	}

	return nil
}

// rotateAPIClientSecrets re-encrypts all API client secrets
func (ae *AuthEncryption) rotateAPIClientSecrets() error {
	var clients []models.APIClient
	if err := ae.db.Find(&clients).Error; err != nil {
		return fmt.Errorf("failed to retrieve API clients: %w", err)
	}

	for _, client := range clients {
		// Decrypt with old key
		plainSecret, err := ae.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt client secret for rotation: %w", err)
		}

		// Re-encrypt with new key
		encryptedSecret, metadata, err := ae.EncryptClientSecret(plainSecret)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt client secret: %w", err)
		}

		// Update in database
		updates := map[string]interface{}{
			"encrypted_client_secret": encryptedSecret,
			"client_secret_metadata":  datatypes.JSON(metadata),
		}

		if err := ae.db.Model(&client).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update rotated client secret: %w", err)
		}
	}

	return nil
}

// rotateSessionTokens re-encrypts all session tokens
func (ae *AuthEncryption) rotateSessionTokens() error {
	var sessions []models.Session
	if err := ae.db.Find(&sessions).Error; err != nil {
		return fmt.Errorf("failed to retrieve sessions: %w", err)
	}

	for _, session := range sessions {
		// Decrypt with old key
		plainToken, err := ae.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt session token for rotation: %w", err)
		}

		// Re-encrypt with new key
		encryptedToken, metadata, err := ae.EncryptSessionToken(plainToken)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt session token: %w", err)
		}

		// Update in database
		updates := map[string]interface{}{
			"encrypted_session_token": encryptedToken,
			"session_token_metadata":  datatypes.JSON(metadata),
		}

		if err := ae.db.Model(&session).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update rotated session token: %w", err)
		}
	}

	return nil
}

// rotateAPITokens re-encrypts all API tokens
func (ae *AuthEncryption) rotateAPITokens() error {
	var tokens []models.APIToken
	if err := ae.db.Find(&tokens).Error; err != nil {
		return fmt.Errorf("failed to retrieve API tokens: %w", err)
	}

	for _, token := range tokens {
		// Decrypt with old key
		plainToken, err := ae.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
		if err != nil {
			return fmt.Errorf("failed to decrypt API token for rotation: %w", err)
		}

		// Re-encrypt with new key
		encryptedToken, metadata, err := ae.EncryptAPIToken(plainToken)
		if err != nil {
			return fmt.Errorf("failed to re-encrypt API token: %w", err)
		}

		// Update in database
		updates := map[string]interface{}{
			"encrypted_token": encryptedToken,
			"token_metadata":  datatypes.JSON(metadata),
		}

		if err := ae.db.Model(&token).Updates(updates).Error; err != nil {
			return fmt.Errorf("failed to update rotated API token: %w", err)
		}
	}

	return nil
}

// GetAuthEncryptionStatus returns the current authentication encryption status
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
