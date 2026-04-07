package encryption

import (
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestDBForSharing(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate models
	err = db.AutoMigrate(&models.SecretNode{}, &models.SecretVersion{}, &models.ShareRecord{})
	require.NoError(t, err)

	return db
}

func TestShareEncryption_ShareSecret(t *testing.T) {
	// Setup
	db := setupTestDBForSharing(t)
	
	// Create test config with encryption disabled for simplicity
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}
	
	// Create encryption services
	secretEncryption := NewSecretEncryption(cfg, ".", db)
	shareEncryption := NewShareEncryption(secretEncryption)
	
	// Create test secret node
	secretNode := &models.SecretNode{
		ID:            1,
		Name:          "test-secret",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		OwnerID:       1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err := db.Create(secretNode).Error
	require.NoError(t, err)
	
	// Create test secret version
	secretVersion := &models.SecretVersion{
		ID:             1,
		SecretNodeID:   secretNode.ID,
		VersionNumber:  1,
		EncryptedValue: []byte("test-value"),
		CreatedAt:      time.Now(),
	}
	err = db.Create(secretVersion).Error
	require.NoError(t, err)
	
	// Test sharing the secret
	err = shareEncryption.ShareSecret(secretVersion, 2)
	assert.NoError(t, err)
}

func TestShareEncryption_RevokeSharedSecret(t *testing.T) {
	// Setup
	db := setupTestDBForSharing(t)
	
	// Create test config with encryption disabled for simplicity
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}
	
	// Create encryption services
	secretEncryption := NewSecretEncryption(cfg, ".", db)
	shareEncryption := NewShareEncryption(secretEncryption)
	
	// Create test share record
	shareRecord := &models.ShareRecord{
		ID:          1,
		SecretID:    1,
		OwnerID:     1,
		RecipientID: 2,
		IsGroup:     false,
		Permission:  "read",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	err := db.Create(shareRecord).Error
	require.NoError(t, err)
	
	// Test revoking the shared secret
	err = shareEncryption.RevokeSharedSecret(shareRecord.ID)
	assert.NoError(t, err)
}

func TestShareEncryption_StoreSharedSecret(t *testing.T) {
	// Setup
	db := setupTestDBForSharing(t)
	
	// Create test config with encryption disabled for simplicity
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}
	
	// Create encryption services
	secretEncryption := NewSecretEncryption(cfg, ".", db)
	shareEncryption := NewShareEncryption(secretEncryption)
	
	// Create test secret node
	secretNode := &models.SecretNode{
		ID:            1,
		Name:          "test-secret",
		NamespaceID:   1,
		ZoneID:        1,
		EnvironmentID: 1,
		OwnerID:       1,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	err := db.Create(secretNode).Error
	require.NoError(t, err)
	
	// Test storing a shared secret
	plaintext := []byte("test-shared-value")
	recipientID := uint(2)
	
	version, err := shareEncryption.StoreSharedSecret(secretNode, plaintext, recipientID)
	require.NoError(t, err)
	assert.NotNil(t, version)
	assert.Equal(t, secretNode.ID, version.SecretNodeID)
	assert.Equal(t, 1, version.VersionNumber)
	
	// Verify the stored value
	var storedVersion models.SecretVersion
	err = db.First(&storedVersion, version.ID).Error
	require.NoError(t, err)
	assert.Equal(t, plaintext, storedVersion.EncryptedValue)
}

func TestShareEncryption_EncryptForRecipient(t *testing.T) {
	// Setup
	db := setupTestDBForSharing(t)
	
	// Create test config with encryption disabled for simplicity
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}
	
	// Create encryption services
	secretEncryption := NewSecretEncryption(cfg, ".", db)
	shareEncryption := NewShareEncryption(secretEncryption)
	
	// Test encrypting for a recipient
	plaintext := []byte("test-value")
	recipientID := uint(2)
	
	encryptedData, metadata, err := shareEncryption.EncryptForRecipient(plaintext, recipientID)
	require.NoError(t, err)
	assert.Equal(t, plaintext, encryptedData) // Since encryption is disabled
	assert.Equal(t, []byte("{}"), metadata)
}

func TestShareEncryption_DecryptSharedSecret(t *testing.T) {
	// Setup
	db := setupTestDBForSharing(t)
	
	// Create test config with encryption disabled for simplicity
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}
	
	// Create encryption services
	secretEncryption := NewSecretEncryption(cfg, ".", db)
	shareEncryption := NewShareEncryption(secretEncryption)
	
	// Test decrypting a shared secret
	encryptedData := []byte("test-encrypted-value")
	recipientID := uint(2)
	
	plaintext, err := shareEncryption.DecryptSharedSecret(encryptedData, recipientID)
	require.NoError(t, err)
	assert.Equal(t, encryptedData, plaintext) // Since encryption is disabled
}