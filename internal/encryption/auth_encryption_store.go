// auth_encryption_store.go — Store/Retrieve DB operations for encrypted auth tokens.
//
// StoreEncryptedAPIClient, RetrieveAPIClientSecret, StoreEncryptedSession,
// RetrieveSessionToken, StoreEncryptedAPIToken, RetrieveAPIToken.
// For encrypt/decrypt see auth_encryption.go. For rotation see auth_encryption_rotate.go.
package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// StoreEncryptedAPIClient encrypts the client secret and persists the API client to the DB.
func (ae *AuthEncryption) StoreEncryptedAPIClient(client *models.APIClient, plainSecret string) error {
	encryptedSecret, metadata, err := ae.EncryptClientSecret(plainSecret)
	if err != nil {
		return fmt.Errorf("failed to encrypt client secret: %w", err)
	}
	client.EncryptedClientSecret = encryptedSecret
	if metadata != nil {
		client.ClientSecretMetadata = models.JSON(metadata)
	}
	if err := ae.db.Create(client).Error; err != nil {
		return fmt.Errorf("failed to store API client: %w", err)
	}
	return nil
}

// RetrieveAPIClientSecret fetches an API client by clientID and decrypts its secret.
func (ae *AuthEncryption) RetrieveAPIClientSecret(clientID string) (string, error) {
	var client models.APIClient
	if err := ae.db.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve API client: %w", err)
	}
	plainSecret, err := ae.DecryptClientSecret(client.EncryptedClientSecret, []byte(client.ClientSecretMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt client secret: %w", err)
	}
	return plainSecret, nil
}

// StoreEncryptedSession encrypts the session token and persists the session to the DB.
func (ae *AuthEncryption) StoreEncryptedSession(session *models.Session, plainToken string) error {
	encryptedToken, metadata, err := ae.EncryptSessionToken(plainToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt session token: %w", err)
	}
	session.EncryptedSessionToken = encryptedToken
	if metadata != nil {
		session.SessionTokenMetadata = models.JSON(metadata)
	}
	if err := ae.db.Create(session).Error; err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}
	return nil
}

// RetrieveSessionToken fetches a session by ID and decrypts its token.
func (ae *AuthEncryption) RetrieveSessionToken(sessionID uint) (string, error) {
	var session models.Session
	if err := ae.db.First(&session, sessionID).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve session: %w", err)
	}
	plainToken, err := ae.DecryptSessionToken(session.EncryptedSessionToken, []byte(session.SessionTokenMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt session token: %w", err)
	}
	return plainToken, nil
}

// StoreEncryptedAPIToken encrypts the API token and persists it to the DB.
func (ae *AuthEncryption) StoreEncryptedAPIToken(token *models.APIToken, plainToken string) error {
	encryptedToken, metadata, err := ae.EncryptAPIToken(plainToken)
	if err != nil {
		return fmt.Errorf("failed to encrypt API token: %w", err)
	}
	token.EncryptedToken = encryptedToken
	if metadata != nil {
		token.TokenMetadata = models.JSON(metadata)
	}
	if err := ae.db.Create(token).Error; err != nil {
		return fmt.Errorf("failed to store API token: %w", err)
	}
	return nil
}

// RetrieveAPIToken fetches an API token by ID and decrypts it.
func (ae *AuthEncryption) RetrieveAPIToken(tokenID uint) (string, error) {
	var token models.APIToken
	if err := ae.db.First(&token, tokenID).Error; err != nil {
		return "", fmt.Errorf("failed to retrieve API token: %w", err)
	}
	plainToken, err := ae.DecryptAPIToken(token.EncryptedToken, []byte(token.TokenMetadata))
	if err != nil {
		return "", fmt.Errorf("failed to decrypt API token: %w", err)
	}
	return plainToken, nil
}
