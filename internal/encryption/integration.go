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

// Initialize initializes the encryption service.
// passphrase is forwarded to the key manager for KEK derivation — never stored.
func (se *SecretEncryption) Initialize(passphrase string) error {
	if !se.service.IsEnabled() {
		return nil // Encryption disabled, skip initialization
	}
	return se.service.Initialize(passphrase)
}

// maxStoreSecretConflictRetries bounds StoreSecret's version-number retry loop
// (#121). Each retry only advances the computed number by one slot, so under N
// truly simultaneous writers on the same secret a losing writer can need close
// to N retries — set well above any realistic concurrent-writer count on one
// secret, bounded so a genuinely broken insert fails instead of looping forever.
const maxStoreSecretConflictRetries = 64

// StoreSecret encrypts and stores a secret in the database, assigning the next
// version number atomically (#121). A concurrent writer for the SAME secret
// (manual RotateSecret racing scheduled auto-rotation, or two concurrent
// updates) used to both compute the SAME MAX(version_number)+1 before either
// committed, producing a duplicate version number — GetLatest then returns one
// non-deterministically (a lost update: the Keyorix-visible value silently
// diverges from whichever upstream credential a rotation backend actually set)
// — or, when the second INSERT's version_number wasn't yet unique-constrained,
// simply succeeded and duplicated it outright. A unique index on
// (secret_node_id, version_number) now makes the losing writer's INSERT fail
// instead of succeeding wrongly; this retries with a freshly computed number
// rather than surfacing that as an error.
func (se *SecretEncryption) StoreSecret(secretNode *models.SecretNode, plaintext []byte) (*models.SecretVersion, error) {
	var lastErr error
	for attempt := 0; attempt < maxStoreSecretConflictRetries; attempt++ {
		version, err := se.tryStoreSecret(secretNode, plaintext)
		if err == nil {
			return version, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// tryStoreSecret is one attempt of StoreSecret: compute the next version number
// and insert, inside a transaction. The encryption AAD binds to the version
// number (SecretAAD), so a conflicting attempt must re-encrypt with the freshly
// computed number, not just retry the insert with the old ciphertext.
func (se *SecretEncryption) tryStoreSecret(secretNode *models.SecretNode, plaintext []byte) (*models.SecretVersion, error) {
	tx := se.db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

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

	// Encrypt the secret with AAD bound to secretID + projectID + versionNumber
	aad := SecretAAD(secretNode.ID, secretNode.ProjectID, nextVersion)
	encryptedData, metadata, err := se.service.EncryptSecretWithAAD(plaintext, aad)
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

	// Fetch the parent SecretNode to get ProjectID for AAD reconstruction
	var secretNode models.SecretNode
	if err := se.db.First(&secretNode, version.SecretNodeID).Error; err != nil {
		return nil, fmt.Errorf("failed to retrieve secret node for AAD: %w", err)
	}

	// Decrypt using AAD-aware path (falls back gracefully for legacy rows)
	aad := SecretAAD(version.SecretNodeID, secretNode.ProjectID, version.VersionNumber)
	plaintext, err := se.service.DecryptSecretWithAAD(version.EncryptedValue, aad)
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
