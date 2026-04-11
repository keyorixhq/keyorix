package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// ShareEncryption handles encryption operations for shared secrets
type ShareEncryption struct {
	service *Service
	db      *gorm.DB
}

// NewShareEncryption creates a new shared secret encryption handler
func NewShareEncryption(secretEncryption *SecretEncryption) *ShareEncryption {
	return &ShareEncryption{
		service: secretEncryption.service,
		db:      secretEncryption.db,
	}
}

// ShareSecret encrypts a secret for a recipient
// This function re-encrypts the secret value for the recipient
// so they can access it with their own key
func (se *ShareEncryption) ShareSecret(secretVersion *models.SecretVersion, recipientID uint) error {
	if !se.service.IsEnabled() {
		// No need to re-encrypt if encryption is disabled
		return nil
	}

	// Get the plaintext value of the secret
	_, err := se.getPlaintext(secretVersion)
	if err != nil {
		return fmt.Errorf("failed to get plaintext for sharing: %w", err)
	}

	// TODO: In a real implementation, we would encrypt with the recipient's public key
	// For now, we'll just use the same encryption as the original secret
	// This is a placeholder for the actual implementation

	// In a real implementation, we would:
	// 1. Get the recipient's public key
	// 2. Encrypt the DEK with the recipient's public key
	// 3. Store the encrypted DEK in the share record
	// 4. When the recipient accesses the secret, they would:
	//    a. Decrypt the DEK with their private key
	//    b. Use the DEK to decrypt the secret value

	return nil
}

// RevokeSharedSecret revokes access to a shared secret
// This function removes the recipient's ability to decrypt the secret
func (se *ShareEncryption) RevokeSharedSecret(shareID uint) error {
	if !se.service.IsEnabled() {
		// No need to do anything if encryption is disabled
		return nil
	}

	// TODO: In a real implementation, we would:
	// 1. Remove the recipient's encrypted DEK
	// 2. If necessary, re-encrypt the secret with a new DEK
	// 3. Update all other recipients' encrypted DEKs with the new DEK

	return nil
}

// getPlaintext retrieves the plaintext value of a secret version
func (se *ShareEncryption) getPlaintext(secretVersion *models.SecretVersion) ([]byte, error) {
	if !se.service.IsEnabled() {
		// Return unencrypted data if encryption is disabled
		return secretVersion.EncryptedValue, nil
	}

	// Decrypt the secret
	plaintext, err := se.service.DecryptSecret(secretVersion.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret for sharing: %w", err)
	}

	return plaintext, nil
}

// EncryptForRecipient encrypts a secret for a specific recipient
func (se *ShareEncryption) EncryptForRecipient(plaintext []byte, recipientID uint) ([]byte, []byte, error) {
	if !se.service.IsEnabled() {
		// Return unencrypted data if encryption is disabled
		return plaintext, []byte("{}"), nil
	}

	// TODO: In a real implementation, we would:
	// 1. Get the recipient's public key
	// 2. Generate a new DEK for this secret
	// 3. Encrypt the plaintext with the DEK
	// 4. Encrypt the DEK with the recipient's public key
	// 5. Return the encrypted plaintext and the encrypted DEK

	// For now, we'll just use the standard encryption
	return se.service.EncryptSecret(plaintext)
}

// DecryptSharedSecret decrypts a shared secret for a recipient
func (se *ShareEncryption) DecryptSharedSecret(encryptedData []byte, recipientID uint) ([]byte, error) {
	if !se.service.IsEnabled() {
		// Return unencrypted data if encryption is disabled
		return encryptedData, nil
	}

	// TODO: In a real implementation, we would:
	// 1. Get the recipient's private key
	// 2. Decrypt the DEK with the recipient's private key
	// 3. Use the DEK to decrypt the secret value

	// For now, we'll just use the standard decryption
	return se.service.DecryptSecret(encryptedData)
}

// StoreSharedSecret stores a shared secret in the database
func (se *ShareEncryption) StoreSharedSecret(secretNode *models.SecretNode, plaintext []byte, recipientID uint) (*models.SecretVersion, error) {
	// Use a transaction to ensure atomicity
	tx := se.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Calculate next version number
	var maxVersion int
	err := tx.Model(&models.SecretVersion{}).
		Where("secret_node_id = ?", secretNode.ID).
		Select("COALESCE(MAX(version_number), 0)").
		Scan(&maxVersion).Error

	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to calculate version number: %w", err)
	}

	nextVersion := maxVersion + 1

	if !se.service.IsEnabled() {
		// Store unencrypted if encryption is disabled
		version := &models.SecretVersion{
			SecretNodeID:   secretNode.ID,
			VersionNumber:  nextVersion,
			EncryptedValue: plaintext,
		}
		if err := tx.Create(version).Error; err != nil {
			tx.Rollback()
			return nil, fmt.Errorf("failed to store unencrypted shared secret: %w", err)
		}
		tx.Commit()
		return version, nil
	}

	// Encrypt the secret for the recipient
	encryptedData, metadata, err := se.EncryptForRecipient(plaintext, recipientID)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to encrypt shared secret: %w", err)
	}

	// Create secret version
	version := &models.SecretVersion{
		SecretNodeID:       secretNode.ID,
		VersionNumber:      nextVersion,
		EncryptedValue:     encryptedData,
		EncryptionMetadata: models.JSON(metadata),
	}

	if err := tx.Create(version).Error; err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to store encrypted shared secret: %w", err)
	}

	tx.Commit()
	return version, nil
}