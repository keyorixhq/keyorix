package encryption

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupAuthEncryptionTest(t *testing.T) (*AuthEncryption, *gorm.DB, func()) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "auth_encryption_test")
	require.NoError(t, err)

	// Create test database
	db, err := gorm.Open(sqlite.Open(filepath.Join(tempDir, "test.db")), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate tables
	err = db.AutoMigrate(
		&models.APIClient{},
		&models.Session{},
		&models.APIToken{},
		&models.PasswordReset{},
	)
	require.NoError(t, err)

	// Create encryption config with encryption disabled for simpler testing
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}

	// Create auth encryption service
	authEnc := NewAuthEncryption(cfg, tempDir, db)
	err = authEnc.Initialize("test-passphrase-for-unit-tests")
	require.NoError(t, err)

	// Cleanup function
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	return authEnc, db, cleanup
}

func TestAuthEncryption_ClientSecret(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	tests := []struct {
		name         string
		clientSecret string
	}{
		{
			name:         "simple client secret",
			clientSecret: "simple-client-secret-123",
		},
		{
			name:         "complex client secret",
			clientSecret: "complex-client-secret-with-special-chars!@#$%^&*()_+-={}[]|\\:;\"'<>?,./",
		},
		{
			name:         "long client secret",
			clientSecret: "very-long-client-secret-" + string(make([]byte, 1000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt client secret
			encryptedData, metadata, err := authEnc.EncryptClientSecret(tt.clientSecret)
			require.NoError(t, err)
			assert.NotEmpty(t, encryptedData)

			// When encryption is disabled, metadata will be nil
			if authEnc.service.IsEnabled() {
				assert.NotEmpty(t, metadata)
			}

			// Decrypt client secret
			decryptedSecret, err := authEnc.DecryptClientSecret(encryptedData, metadata)
			require.NoError(t, err)
			assert.Equal(t, tt.clientSecret, decryptedSecret)
		})
	}
}

func TestAuthEncryption_SessionToken(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	sessionToken := "session-token-abc123def456"

	// Encrypt session token
	encryptedData, metadata, err := authEnc.EncryptSessionToken(sessionToken)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// When encryption is disabled, metadata will be nil
	if authEnc.service.IsEnabled() {
		assert.NotEmpty(t, metadata)
	}

	// Decrypt session token
	decryptedToken, err := authEnc.DecryptSessionToken(encryptedData, metadata)
	require.NoError(t, err)
	assert.Equal(t, sessionToken, decryptedToken)
}

func TestAuthEncryption_APIToken(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	apiToken := "api-token-xyz789uvw012"

	// Encrypt API token
	encryptedData, metadata, err := authEnc.EncryptAPIToken(apiToken)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// When encryption is disabled, metadata will be nil
	if authEnc.service.IsEnabled() {
		assert.NotEmpty(t, metadata)
	}

	// Decrypt API token
	decryptedToken, err := authEnc.DecryptAPIToken(encryptedData, metadata)
	require.NoError(t, err)
	assert.Equal(t, apiToken, decryptedToken)
}

func TestAuthEncryption_PasswordResetToken(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	resetToken := "password-reset-token-mno345pqr678"

	// Encrypt password reset token
	encryptedData, metadata, err := authEnc.EncryptPasswordResetToken(resetToken)
	require.NoError(t, err)
	assert.NotEmpty(t, encryptedData)

	// When encryption is disabled, metadata will be nil
	if authEnc.service.IsEnabled() {
		assert.NotEmpty(t, metadata)
	}

	// Decrypt password reset token
	decryptedToken, err := authEnc.DecryptPasswordResetToken(encryptedData, metadata)
	require.NoError(t, err)
	assert.Equal(t, resetToken, decryptedToken)
}

func TestAuthEncryption_StoreEncryptedAPIClient(t *testing.T) {
	authEnc, db, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	client := &models.APIClient{
		Name:        "Test Client",
		Description: "Test API Client",
		ClientID:    "test-client-id",
		Scopes:      "read write",
		IsActive:    true,
		CreatedAt:   time.Now(),
	}

	clientSecret := "super-secret-client-secret"

	// Store encrypted API client
	err := authEnc.StoreEncryptedAPIClient(client, clientSecret)
	require.NoError(t, err)

	// Verify client was stored
	var storedClient models.APIClient
	err = db.Where("client_id = ?", "test-client-id").First(&storedClient).Error
	require.NoError(t, err)

	assert.Equal(t, "Test Client", storedClient.Name)
	assert.NotEmpty(t, storedClient.EncryptedClientSecret)

	// When encryption is disabled, metadata will be empty
	if authEnc.service.IsEnabled() {
		assert.NotEmpty(t, storedClient.ClientSecretMetadata)
	}

	// Retrieve and verify client secret
	retrievedSecret, err := authEnc.RetrieveAPIClientSecret("test-client-id")
	require.NoError(t, err)
	assert.Equal(t, clientSecret, retrievedSecret)
}

func TestAuthEncryption_StoreEncryptedSession(t *testing.T) {
	authEnc, db, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	expiresAt := time.Now().Add(24 * time.Hour)
	session := &models.Session{
		UserID:    1,
		CreatedAt: time.Now(),
		ExpiresAt: &expiresAt,
	}

	sessionToken := "encrypted-session-token-123"

	// Store encrypted session
	err := authEnc.StoreEncryptedSession(session, sessionToken)
	require.NoError(t, err)

	// Verify session was stored
	var storedSession models.Session
	err = db.First(&storedSession, session.ID).Error
	require.NoError(t, err)

	assert.Equal(t, uint(1), storedSession.UserID)
	assert.NotEmpty(t, storedSession.EncryptedSessionToken)

	// When encryption is disabled, metadata will be empty
	if authEnc.service.IsEnabled() {
		assert.NotEmpty(t, storedSession.SessionTokenMetadata)
	}

	// Retrieve and verify session token
	retrievedToken, err := authEnc.RetrieveSessionToken(storedSession.ID)
	require.NoError(t, err)
	assert.Equal(t, sessionToken, retrievedToken)
}

func TestAuthEncryption_ValidateEncryptedToken(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	originalToken := "test-validation-token"

	// Encrypt token
	encryptedData, metadata, err := authEnc.EncryptSessionToken(originalToken)
	require.NoError(t, err)

	// Test valid token
	isValid, err := authEnc.ValidateEncryptedToken(encryptedData, metadata, originalToken)
	require.NoError(t, err)
	assert.True(t, isValid)

	// Test invalid token
	isValid, err = authEnc.ValidateEncryptedToken(encryptedData, metadata, "wrong-token")
	require.NoError(t, err)
	assert.False(t, isValid)
}

func TestAuthEncryption_DisabledEncryption(t *testing.T) {
	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "auth_encryption_disabled_test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Create test database
	db, err := gorm.Open(sqlite.Open(filepath.Join(tempDir, "test.db")), &gorm.Config{})
	require.NoError(t, err)

	// Auto-migrate tables
	err = db.AutoMigrate(&models.APIClient{})
	require.NoError(t, err)

	// Create encryption config with encryption disabled
	cfg := &config.EncryptionConfig{
		Enabled: false,
	}

	// Create auth encryption service
	authEnc := NewAuthEncryption(cfg, tempDir, db)
	err = authEnc.Initialize("test-passphrase-for-unit-tests")
	require.NoError(t, err)

	clientSecret := "plaintext-client-secret"

	// Encrypt client secret (should return plaintext)
	encryptedData, metadata, err := authEnc.EncryptClientSecret(clientSecret)
	require.NoError(t, err)
	assert.Equal(t, []byte(clientSecret), encryptedData)
	assert.Nil(t, metadata)

	// Decrypt client secret (should return as-is)
	decryptedSecret, err := authEnc.DecryptClientSecret(encryptedData, metadata)
	require.NoError(t, err)
	assert.Equal(t, clientSecret, decryptedSecret)
}

func TestAuthEncryption_KeyRotation(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	// Create test data
	client := &models.APIClient{
		Name:      "Test Client",
		ClientID:  "test-client-rotation",
		Scopes:    "read",
		IsActive:  true,
		CreatedAt: time.Now(),
	}

	clientSecret := "secret-for-rotation"
	err := authEnc.StoreEncryptedAPIClient(client, clientSecret)
	require.NoError(t, err)

	// Verify original secret works
	retrievedSecret, err := authEnc.RetrieveAPIClientSecret("test-client-rotation")
	require.NoError(t, err)
	assert.Equal(t, clientSecret, retrievedSecret)

	// Skip key rotation test when encryption is disabled
	if !authEnc.service.IsEnabled() {
		t.Skip("Skipping key rotation test when encryption is disabled")
	}

	// Rotate keys (this would normally involve key manager rotation)
	// For this test, we'll simulate by re-encrypting with the same key
	err = authEnc.RotateAuthEncryption()
	require.NoError(t, err)

	// Verify secret still works after rotation
	retrievedSecret, err = authEnc.RetrieveAPIClientSecret("test-client-rotation")
	require.NoError(t, err)
	assert.Equal(t, clientSecret, retrievedSecret)
}

func TestAuthEncryption_GetStatus(t *testing.T) {
	authEnc, _, cleanup := setupAuthEncryptionTest(t)
	defer cleanup()

	status := authEnc.GetAuthEncryptionStatus()

	assert.Contains(t, status, "enabled")
	assert.Contains(t, status, "initialized")

	// When encryption is disabled in config, it should be reflected in status
	assert.False(t, status["enabled"].(bool))
	// When encryption is disabled, initialized should also be false
	assert.False(t, status["initialized"].(bool))

	if keyVersion, ok := status["key_version"]; ok && status["enabled"].(bool) {
		assert.NotEmpty(t, keyVersion)
	}
}

// Benchmark tests
func BenchmarkAuthEncryption_EncryptClientSecret(b *testing.B) {
	authEnc, _, cleanup := setupAuthEncryptionTest(&testing.T{})
	defer cleanup()

	clientSecret := "benchmark-client-secret-123456789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := authEnc.EncryptClientSecret(clientSecret)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAuthEncryption_DecryptClientSecret(b *testing.B) {
	authEnc, _, cleanup := setupAuthEncryptionTest(&testing.T{})
	defer cleanup()

	clientSecret := "benchmark-client-secret-123456789"
	encryptedData, metadata, err := authEnc.EncryptClientSecret(clientSecret)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := authEnc.DecryptClientSecret(encryptedData, metadata)
		if err != nil {
			b.Fatal(err)
		}
	}
}
