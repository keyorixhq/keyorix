package encryption

import (
	"fmt"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"gorm.io/gorm"
)

// SecretEncryption handles encryption operations for secrets in the database
type SecretEncryption struct {
	service *Service
	db      *gorm.DB
}

// NewSecretEncryption creates a new secret encryption handler
func NewSecretEncryption(cfg *config.EncryptionConfig, baseDir string, db *gorm.DB) *SecretEncryption {
	return &SecretEncryption{
		service: NewService(cfg, baseDir),
		db:      db,
	}
}

// Initialize initializes the encryption service
func (se *SecretEncryption) Initialize() error {
	if !se.service.IsEnabled() {
		return nil // Encryption disabled, skip initialization
	}
	return se.service.Initialize()
}

// StoreSecret encrypts and stores a secret in the database
func (se *SecretEncryption) StoreSecret(secretNode *models.SecretNode, plaintext []byte) (*models.SecretVersion, error) {
	// Use a transaction to ensure atomicity and prevent race conditions
	tx := se.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	// Calculate next version number within the transaction
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
			return nil, fmt.Errorf("failed to store unencrypted secret: %w", err)
		}
		tx.Commit()
		return version, nil
	}

	// Encrypt the secret
	encryptedData, metadata, err := se.service.EncryptSecret(plaintext)
	if err != nil {
		tx.Rollback()
		return nil, fmt.Errorf("failed to encrypt secret: %w", err)
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
		return nil, fmt.Errorf("failed to store encrypted secret: %w", err)
	}

	tx.Commit()
	return version, nil
}

// RetrieveSecret retrieves and decrypts a secret from the database
func (se *SecretEncryption) RetrieveSecret(versionID uint) ([]byte, error) {
	var version models.SecretVersion
	if err := se.db.First(&version, versionID).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve secret version: %w", err)
	}

	if !se.service.IsEnabled() {
		// Return unencrypted data if encryption is disabled
		return version.EncryptedValue, nil
	}

	// Decrypt the secret
	plaintext, err := se.service.DecryptSecret(version.EncryptedValue)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt secret: %w", err)
	}

	return plaintext, nil
}

// StoreLargeSecret encrypts and stores a large secret using chunking
func (se *SecretEncryption) StoreLargeSecret(secretNode *models.SecretNode, plaintext []byte, chunkSizeKB int) ([]*models.SecretVersion, error) {
	if !se.service.IsEnabled() {
		// Store as single version if encryption is disabled
		version, err := se.StoreSecret(secretNode, plaintext)
		if err != nil {
			return nil, err
		}
		return []*models.SecretVersion{version}, nil
	}

	// Encrypt with chunking
	encryptedChunks, metadataChunks, err := se.service.EncryptLargeSecret(plaintext, chunkSizeKB)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt large secret: %w", err)
	}

	var versions []*models.SecretVersion
	for i, encryptedChunk := range encryptedChunks {
		version := &models.SecretVersion{
			SecretNodeID:       secretNode.ID,
			VersionNumber:      i + 1,
			EncryptedValue:     encryptedChunk,
			EncryptionMetadata: models.JSON(metadataChunks[i]),
		}

		if err := se.db.Create(version).Error; err != nil {
			return nil, fmt.Errorf("failed to store encrypted chunk %d: %w", i, err)
		}

		versions = append(versions, version)
	}

	return versions, nil
}

// RetrieveLargeSecret retrieves and decrypts a large secret from chunks
func (se *SecretEncryption) RetrieveLargeSecret(secretNodeID uint) ([]byte, error) {
	var versions []models.SecretVersion
	if err := se.db.Where("secret_node_id = ?", secretNodeID).Order("version_number").Find(&versions).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve secret versions: %w", err)
	}

	if len(versions) == 0 {
		return nil, fmt.Errorf("no secret versions found")
	}

	if !se.service.IsEnabled() {
		// Concatenate unencrypted chunks if encryption is disabled
		var result []byte
		for _, version := range versions {
			result = append(result, version.EncryptedValue...)
		}
		return result, nil
	}

	// Check if this is a chunked secret by examining metadata
	if len(versions) == 1 {
		// Single version, decrypt normally
		return se.service.DecryptSecret(versions[0].EncryptedValue)
	}

	// Multiple versions, decrypt as chunks
	var encryptedChunks [][]byte
	for _, version := range versions {
		encryptedChunks = append(encryptedChunks, version.EncryptedValue)
	}

	plaintext, err := se.service.DecryptLargeSecret(encryptedChunks)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt large secret: %w", err)
	}

	return plaintext, nil
}

// RotateSecretEncryption re-encrypts a secret with new keys
func (se *SecretEncryption) RotateSecretEncryption(versionID uint) error {
	if !se.service.IsEnabled() {
		return fmt.Errorf("encryption is disabled")
	}

	// Retrieve and decrypt with old key
	plaintext, err := se.RetrieveSecret(versionID)
	if err != nil {
		return fmt.Errorf("failed to retrieve secret for rotation: %w", err)
	}

	// Re-encrypt with new key
	encryptedData, metadata, err := se.service.EncryptSecret(plaintext)
	if err != nil {
		return fmt.Errorf("failed to re-encrypt secret: %w", err)
	}

	// Update the version
	updates := map[string]interface{}{
		"encrypted_value":     encryptedData,
		"encryption_metadata": models.JSON(metadata),
	}

	if err := se.db.Model(&models.SecretVersion{}).Where("id = ?", versionID).Updates(updates).Error; err != nil {
		return fmt.Errorf("failed to update rotated secret: %w", err)
	}

	return nil
}

// GetEncryptionStatus returns the current encryption status
func (se *SecretEncryption) GetEncryptionStatus() map[string]interface{} {
	status := map[string]interface{}{
		"enabled":     se.service.IsEnabled(),
		"initialized": se.service.IsInitialized(),
	}

	if se.service.IsInitialized() {
		status["key_version"] = se.service.GetKeyVersion()
	}

	return status
}

// ValidateEncryption validates the encryption setup
func (se *SecretEncryption) ValidateEncryption() error {
	if !se.service.IsEnabled() {
		return nil
	}

	if !se.service.IsInitialized() {
		return fmt.Errorf("encryption service not initialized")
	}

	return se.service.ValidateKeyFiles()
}
