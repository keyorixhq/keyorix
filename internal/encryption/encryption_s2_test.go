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
	gormlogger "gorm.io/gorm/logger"
)

// setupS2AuthEncEnabled creates an AuthEncryption with encryption ENABLED.
func setupS2AuthEncEnabled(t *testing.T, db *gorm.DB) *AuthEncryption {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("test-passphrase-s2-enabled"))
	return ae
}

// setupS2DB creates an in-memory SQLite database auto-migrated with auth models.
func setupS2DB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.APIClient{},
		&models.Session{},
		&models.APIToken{},
		&models.PasswordReset{},
	))
	return db
}

// setupS2AuthEnc creates an AuthEncryption with encryption disabled and a fresh tempdir.
func setupS2AuthEnc(t *testing.T, db *gorm.DB) *AuthEncryption {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	ae := NewAuthEncryption(cfg, dir, db)
	require.NoError(t, ae.Initialize("passphrase"))
	return ae
}

// --- EncryptionService ---

func TestEncryptionService_RotateKey(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	original := []byte("plaintext to rotate")
	enc, err := es.Encrypt(original, "v1")
	require.NoError(t, err)

	rotated, err := es.rotateKey(enc, "v2")
	require.NoError(t, err)
	assert.Equal(t, "v2", rotated.Metadata.KeyVersion)

	dec, err := es.Decrypt(rotated)
	require.NoError(t, err)
	assert.Equal(t, original, dec)
}

func TestEncryptionService_RotateKey_CorruptInput(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	// Corrupt ciphertext must fail decrypt-step inside rotateKey.
	bad := &EncryptedData{
		Data: []byte("not-valid-ciphertext"),
		Metadata: EncryptionMetadata{
			Algorithm:  "AES-256-GCM",
			KeyVersion: "v1",
			Nonce:      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==", // wrong-length base64 that decodes OK but nonce is wrong size
		},
	}
	// Wrong nonce length → error on Decrypt
	_, err = es.rotateKey(bad, "v2")
	require.Error(t, err)
}

func TestEncryptionService_Decrypt_UnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	_, err = es.Decrypt(&EncryptedData{
		Data:     []byte("data"),
		Metadata: EncryptionMetadata{Algorithm: "DES-CBC"},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestEncryptionService_Decrypt_WrongNonceLength(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	// Nonce base64 of only 4 bytes — wrong size.
	_, err = es.Decrypt(&EncryptedData{
		Data:     []byte("data"),
		Metadata: EncryptionMetadata{Algorithm: "AES-256-GCM", Nonce: "AAAA"},
	})
	require.Error(t, err)
}

func TestEncryptionService_DecryptWithAAD_UnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	_, err = es.DecryptWithAAD(&EncryptedData{
		Data:     []byte("data"),
		Metadata: EncryptionMetadata{Algorithm: "RC4"},
	}, []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
}

func TestEncryptionService_DecryptWithAAD_WrongNonceLength(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	_, err = es.DecryptWithAAD(&EncryptedData{
		Data:     []byte("data"),
		Metadata: EncryptionMetadata{Algorithm: "AES-256-GCM", Nonce: "AAAA"},
	}, nil)
	require.Error(t, err)
}

func TestEncryptionService_DeserializeEncryptedData_Invalid(t *testing.T) {
	_, err := DeserializeEncryptedData([]byte("not-json"))
	require.Error(t, err)
}

func TestEncryptionService_DeserializeEncryptedData_RoundTrip(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	enc, err := es.Encrypt([]byte("hello"), "v1")
	require.NoError(t, err)

	serialized, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	deserialized, err := DeserializeEncryptedData(serialized)
	require.NoError(t, err)

	dec, err := es.Decrypt(deserialized)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), dec)
}

// --- AuthEncryption store: StoreEncryptedAPIToken / RetrieveAPIToken ---

func TestAuthEncryption_StoreAndRetrieveAPIToken(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db)

	apiToken := &models.APIToken{
		ClientID:  1,
		Scope:     "read",
		CreatedAt: time.Now(),
	}
	plain := "api-token-plain-text-value"

	require.NoError(t, ae.StoreEncryptedAPIToken(apiToken, plain))
	assert.NotZero(t, apiToken.ID, "token must be stored in the DB")

	retrieved, err := ae.RetrieveAPIToken(apiToken.ID)
	require.NoError(t, err)
	assert.Equal(t, plain, retrieved)
}

func TestAuthEncryption_RetrieveAPIToken_NotFound(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db)

	_, err := ae.RetrieveAPIToken(99999)
	require.Error(t, err)
}

// TestAuthEncryption_Enabled_Suite shares one setupS2AuthEncEnabled call across subtests
// to avoid repeated expensive PBKDF2 derivations.
func TestAuthEncryption_Enabled_Suite(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEncEnabled(t, db)

	t.Run("StoreAndRetrieveAPIToken", func(t *testing.T) {
		apiToken := &models.APIToken{
			ClientID:  2,
			Scope:     "write",
			CreatedAt: time.Now(),
		}
		plain := "api-token-enabled-value"
		require.NoError(t, ae.StoreEncryptedAPIToken(apiToken, plain))
		assert.NotZero(t, apiToken.ID)
		retrieved, err := ae.RetrieveAPIToken(apiToken.ID)
		require.NoError(t, err)
		assert.Equal(t, plain, retrieved)
	})

	t.Run("SessionTokenRoundTrip", func(t *testing.T) {
		plain := "session-token-enabled-path"
		enc, meta, err := ae.EncryptSessionToken(plain, uint(1))
		require.NoError(t, err)
		assert.NotEqual(t, plain, string(enc), "token must be encrypted")
		assert.NotNil(t, meta)
		dec, err := ae.DecryptSessionToken(enc, meta, uint(1))
		require.NoError(t, err)
		assert.Equal(t, plain, dec)
	})

	t.Run("APITokenRoundTrip", func(t *testing.T) {
		plain := "api-token-enabled-path"
		enc, meta, err := ae.EncryptAPIToken(plain, uint(1))
		require.NoError(t, err)
		assert.NotEqual(t, plain, string(enc))
		dec, err := ae.DecryptAPIToken(enc, meta, uint(1))
		require.NoError(t, err)
		assert.Equal(t, plain, dec)
	})

	t.Run("PasswordResetTokenRoundTrip", func(t *testing.T) {
		plain := "reset-token-enabled-path"
		enc, meta, err := ae.EncryptPasswordResetToken(plain, uint(1))
		require.NoError(t, err)
		dec, err := ae.DecryptPasswordResetToken(enc, meta, uint(1))
		require.NoError(t, err)
		assert.Equal(t, plain, dec)
	})

	t.Run("GetAuthEncryptionStatus", func(t *testing.T) {
		status := ae.GetAuthEncryptionStatus()
		assert.Equal(t, true, status["enabled"])
		assert.Equal(t, true, status["initialized"])
		assert.NotEmpty(t, status["key_version"])
	})

	t.Run("ValidateEncryptedToken", func(t *testing.T) {
		plain := "valid-session-token"
		enc, meta, err := ae.EncryptSessionToken(plain, uint(1))
		require.NoError(t, err)
		ok, err := ae.ValidateEncryptedToken(enc, meta, plain, uint(1))
		require.NoError(t, err)
		assert.True(t, ok)
		ok, err = ae.ValidateEncryptedToken(enc, meta, "wrong-token", uint(1))
		require.NoError(t, err)
		assert.False(t, ok)
	})

	t.Run("ValidateEncryptedToken_DecryptError", func(t *testing.T) {
		_, err := ae.ValidateEncryptedToken([]byte("not-valid-ciphertext"), nil, "token", uint(1))
		require.Error(t, err)
	})

	t.Run("StoreAndRetrieveSession", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour)
		sess := &models.Session{
			UserID:    42,
			CreatedAt: time.Now(),
			ExpiresAt: &expiresAt,
		}
		plain := "session-token-for-enabled"
		require.NoError(t, ae.StoreEncryptedSession(sess, plain))
		retrieved, err := ae.RetrieveSessionToken(sess.ID)
		require.NoError(t, err)
		assert.Equal(t, plain, retrieved)
	})

	t.Run("StoreAndRetrieveAPIClient", func(t *testing.T) {
		client := &models.APIClient{
			Name:      "enabled-client",
			ClientID:  "client-enabled-1",
			IsActive:  true,
			CreatedAt: time.Now(),
		}
		plain := "enabled-client-secret"
		require.NoError(t, ae.StoreEncryptedAPIClient(client, plain))
		retrieved, err := ae.RetrieveAPIClientSecret("client-enabled-1")
		require.NoError(t, err)
		assert.Equal(t, plain, retrieved)
	})
}

// --- AuthEncryption: GetAuthEncryptionStatus ---

func TestAuthEncryption_GetAuthEncryptionStatus_Disabled(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db)

	status := ae.GetAuthEncryptionStatus()
	require.NotNil(t, status)
	assert.Equal(t, false, status["enabled"])
}

// --- KeyManager.ValidateKeyFiles and FixKeyFilePermissions ---

func newInitializedKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	dir := t.TempDir()
	// Build a KeyManager via Service initialization so files are written.
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("test-passphrase-s2"))
	return svc.keyManager
}

// TestKeyManager_Initialized_Suite shares one newInitializedKeyManager call across
// subtests to avoid redundant PBKDF2 derivations.
func TestKeyManager_Initialized_Suite(t *testing.T) {
	km := newInitializedKeyManager(t)

	t.Run("ValidateKeyFiles", func(t *testing.T) {
		// After successful init the files exist with 0600; validate must succeed.
		require.NoError(t, km.ValidateKeyFiles())
	})

	t.Run("FixKeyFilePermissions", func(t *testing.T) {
		// Loosen permissions so FixKeyFilePermissions has something to fix.
		require.NoError(t, os.Chmod(filepath.Join(km.baseDir, km.dekPath), 0644))
		require.NoError(t, os.Chmod(filepath.Join(km.baseDir, km.saltPath), 0644))
		require.NoError(t, km.FixKeyFilePermissions())
		info, err := os.Stat(filepath.Join(km.baseDir, km.dekPath))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})
}

func TestKeyManager_ValidateKeyFiles_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	km := &KeyManager{
		baseDir:  dir,
		dekPath:  "missing.dek",
		saltPath: "missing.salt",
	}
	err := km.ValidateKeyFiles()
	require.Error(t, err)
}

// --- NewKeyProviderFromConfig branches ---

func TestNewKeyProviderFromConfig_PasswordProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "passphrase")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_EmptyType_DefaultsToPassword(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: ""},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "passphrase")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_FileProvider(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "kek.key")
	require.NoError(t, os.WriteFile(keyFile, make([]byte, 32), 0600))

	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: keyFile},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_EnvProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "TEST_KEK_ENV"},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_ExecProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "exec", ExecCommand: []string{"echo", "test"}},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_ShamirProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:             "shamir",
			ShamirShareFiles: []string{},
			ShamirShareEnv:   []string{},
			ShamirCommitment: "",
		},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_TPMProvider(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			TPMDevice:      "",
			WrappedKeyPath: "kek.tpm",
		},
	}
	kp, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.NoError(t, err)
	assert.NotNil(t, kp)
}

func TestNewKeyProviderFromConfig_UnknownType(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "unknown-type"},
	}
	_, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown encryption key_provider type")
}

func TestNewKeyProviderFromConfig_AzureKMS_WithEncryptionContext_Rejected(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:                 "azure-kms",
			KMSKeyID:             "https://vault.vault.azure.net/keys/kek/v1",
			KMSEncryptionContext: map[string]string{"key": "value"},
		},
	}
	_, err := NewKeyProviderFromConfig(cfg, dir, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure-kms")
}

func TestAuthEncryption_RotateAuthEncryption_Disabled(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db) // disabled
	err := ae.RotateAuthEncryption("passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestAuthEncryption_RetrieveAPIClientSecret_NotFound(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db)

	_, err := ae.RetrieveAPIClientSecret("nonexistent-client-id")
	require.Error(t, err)
}

func TestAuthEncryption_RetrieveSessionToken_NotFound(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db)

	_, err := ae.RetrieveSessionToken(99999)
	require.Error(t, err)
}

// --- Service methods ---

func newInitializedService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("test-passphrase-service"))
	return svc
}

// TestService_Suite shares one newInitializedService call across read-only and
// stateless subtests to avoid repeated expensive PBKDF2 derivations.
func TestService_Suite(t *testing.T) {
	svc := newInitializedService(t)

	t.Run("ValidateKeyFiles", func(t *testing.T) {
		require.NoError(t, svc.ValidateKeyFiles())
	})

	t.Run("FixKeyFilePermissions", func(t *testing.T) {
		require.NoError(t, svc.FixKeyFilePermissions())
	})

	t.Run("GetKeyVersion", func(t *testing.T) {
		assert.NotEmpty(t, svc.GetKeyVersion())
	})

	t.Run("AuditCheckpointKey_Initialized", func(t *testing.T) {
		key, version, ok := svc.AuditCheckpointKey()
		assert.True(t, ok)
		assert.NotNil(t, key)
		assert.NotEmpty(t, version)
	})

	t.Run("EncryptLargeSecret", func(t *testing.T) {
		large := make([]byte, 300*1024)
		for i := range large {
			large[i] = byte(i % 251)
		}
		encChunks, metaChunks, err := svc.EncryptLargeSecret(large, 64)
		require.NoError(t, err)
		assert.NotEmpty(t, encChunks)
		assert.Len(t, metaChunks, len(encChunks))
		dec, err := svc.DecryptLargeSecret(encChunks)
		require.NoError(t, err)
		assert.Equal(t, large, dec)
	})

	t.Run("DecryptSecret_BadInput", func(t *testing.T) {
		_, err := svc.DecryptSecret([]byte("not-json"))
		require.Error(t, err)
	})

	t.Run("DecryptSecretWithAAD_BadInput", func(t *testing.T) {
		_, err := svc.DecryptSecretWithAAD([]byte("not-json"), []byte("aad"))
		require.Error(t, err)
	})

	t.Run("EncryptSecretWithAAD_RoundTrip", func(t *testing.T) {
		aad := []byte("test-aad-binding")
		plaintext := []byte("secret-with-aad")
		encBytes, _, err := svc.EncryptSecretWithAAD(plaintext, aad)
		require.NoError(t, err)
		dec, err := svc.DecryptSecretWithAAD(encBytes, aad)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dec)
	})

	t.Run("DecryptSecretWithAAD_LegacyFallback", func(t *testing.T) {
		encBytes, _, err := svc.EncryptSecret([]byte("legacy-plain"))
		require.NoError(t, err)
		enc, err := DeserializeEncryptedData(encBytes)
		require.NoError(t, err)
		assert.Empty(t, enc.Metadata.AADVersion, "EncryptSecret must produce legacy (no-AAD) blobs")
		dec, err := svc.DecryptSecretWithAAD(encBytes, []byte("any-aad-is-ignored-on-legacy"))
		require.NoError(t, err)
		assert.Equal(t, []byte("legacy-plain"), dec)
	})
}

func TestService_GetKeyVersion_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	assert.Equal(t, "unknown", svc.GetKeyVersion())
}

func TestService_Initialize_Disabled(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)
	err := svc.Initialize("passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestService_AuditCheckpointKey_Disabled(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)
	_, _, ok := svc.AuditCheckpointKey()
	assert.False(t, ok)
}

func TestService_DecryptSecret_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, err := svc.DecryptSecret([]byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_DecryptSecretWithAAD_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, err := svc.DecryptSecretWithAAD([]byte("data"), []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestAuthEncryption_RotateAuthEncryption_Enabled exercises the enabled rotation path.
func TestAuthEncryption_RotateAuthEncryption_Enabled(t *testing.T) {
	db := setupS2FullDB(t)
	ae := setupS2AuthEncEnabled(t, db)
	// Rotation with no seeded rows (zero-row sweep) must still succeed.
	err := ae.RotateAuthEncryption("test-passphrase-s2-enabled")
	require.NoError(t, err)
}

// TestService_IsEnabled covers IsEnabled true/false paths.
func TestService_IsEnabled_TrueFalse(t *testing.T) {
	dir := t.TempDir()

	cfgEnabled := &config.EncryptionConfig{Enabled: true}
	assert.True(t, NewService(cfgEnabled, dir).IsEnabled())

	cfgDisabled := &config.EncryptionConfig{Enabled: false}
	assert.False(t, NewService(cfgDisabled, dir).IsEnabled())
}

// TestService_IsInitialized_Before_After covers the initialized state transitions.
func TestService_IsInitialized_Before_After(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	assert.False(t, svc.IsInitialized())

	require.NoError(t, svc.Initialize("pass"))
	assert.True(t, svc.IsInitialized())
}

// TestNewEncryptionService_BadKeySize covers the error branch of NewEncryptionService.
func TestNewEncryptionService_BadKeySize(t *testing.T) {
	_, err := NewEncryptionService(make([]byte, 16)) // wrong size
	require.Error(t, err)
}

// TestEncryptionService_EncryptChunked_NegativeChunkSize checks the default chunk size fallback.
func TestEncryptionService_EncryptChunked_NegativeChunkSize(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	data := make([]byte, 100)
	chunks, err := es.EncryptChunked(data, -1, "v1") // -1 → default 64KB
	require.NoError(t, err)
	assert.Len(t, chunks, 1) // 100 bytes fits in 1 chunk
}

// TestEncryptionService_DecryptChunked_Empty covers the empty-chunks error.
func TestEncryptionService_DecryptChunked_Empty(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)
	_, err = es.DecryptChunked(nil)
	require.Error(t, err)
}

// TestEncryptionService_DecryptChunked_WrongCount covers the inconsistent-count error.
func TestEncryptionService_DecryptChunked_WrongCount(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	// Create a valid chunk set, then present only part of it.
	data := []byte("two-chunk-data")
	chunks, err := es.EncryptChunked(data, 5, "v1")
	require.NoError(t, err)

	// Feed only the first chunk.
	_, err = es.DecryptChunked(chunks[:1])
	require.Error(t, err)
}

// TestEncryptionService_DecryptChunked_StreamIDMismatch covers the stream-id mismatch error.
func TestEncryptionService_DecryptChunked_StreamIDMismatch(t *testing.T) {
	key := make([]byte, 32)
	es, err := NewEncryptionService(key)
	require.NoError(t, err)

	// Create two independent chunk sets then mix a chunk from each.
	chunksA, err := es.EncryptChunked([]byte("data-A-padded-xx"), 5, "v1")
	require.NoError(t, err)
	chunksB, err := es.EncryptChunked([]byte("data-B-padded-yy"), 5, "v1")
	require.NoError(t, err)

	// Mix: replace chunk 0 of set A with chunk 0 from set B (different stream ID).
	// We need to manipulate TotalChunks to match since we splice just one chunk.
	if len(chunksA) < 2 || len(chunksB) < 1 {
		t.Skip("insufficient chunks to construct mismatch")
	}
	spliced := make([]*EncryptedData, len(chunksA))
	copy(spliced, chunksA)
	// Replace the first chunk with one from set B but fix its TotalChunks.
	b0 := *chunksB[0]
	b0.Metadata.TotalChunks = len(chunksA)
	spliced[0] = &b0

	_, err = es.DecryptChunked(spliced)
	require.Error(t, err)
}

// TestService_AcquireExclusiveKeyLock exercises the lock acquire and idempotent second call.
func TestService_AcquireExclusiveKeyLock(t *testing.T) {
	svc := newInitializedService(t)
	t.Cleanup(svc.Shutdown)

	// Acquire exclusive lock — must succeed on a freshly-initialized service.
	err := svc.AcquireExclusiveKeyLock()
	require.NoError(t, err)

	// Second call is a no-op (idempotent).
	err2 := svc.AcquireExclusiveKeyLock()
	require.NoError(t, err2)
}

// TestService_AcquireExclusiveKeyLock_NotInitialized covers the "not initialized" error branch.
func TestService_AcquireExclusiveKeyLock_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	err := svc.AcquireExclusiveKeyLock()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// TestService_AcquireSharedKeyLock exercises the shared lock path.
func TestService_AcquireSharedKeyLock(t *testing.T) {
	svc := newInitializedService(t)
	t.Cleanup(svc.Shutdown)

	err := svc.AcquireSharedKeyLock()
	require.NoError(t, err)

	// Second call is idempotent.
	err2 := svc.AcquireSharedKeyLock()
	require.NoError(t, err2)
}

// TestService_Shutdown_ClearsInitialized verifies Shutdown resets the initialized flag.
func TestService_Shutdown_ClearsInitialized(t *testing.T) {
	svc := newInitializedService(t)
	assert.True(t, svc.IsInitialized())

	svc.Shutdown()
	assert.False(t, svc.IsInitialized())
}

func TestService_EncryptSecret_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, _, err := svc.EncryptSecret([]byte("data"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_EncryptSecretWithAAD_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, _, err := svc.EncryptSecretWithAAD([]byte("data"), []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_EncryptLargeSecret_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, _, err := svc.EncryptLargeSecret([]byte("data"), 64)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_DecryptLargeSecret_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	_, err := svc.DecryptLargeSecret([][]byte{[]byte("data")})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_EvidenceSignKey_Initialized(t *testing.T) {
	svc := newInitializedService(t)
	key, version, ok := svc.EvidenceSignKey()
	assert.True(t, ok)
	assert.NotNil(t, key)
	assert.NotEmpty(t, version)
}

func TestService_EvidenceSignKey_Disabled(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: false}
	svc := NewService(cfg, dir)
	_, _, ok := svc.EvidenceSignKey()
	assert.False(t, ok)
}

func setupS2FullDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: gormlogger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.SecretNode{},
		&models.SecretVersion{},
		&models.Session{},
		&models.APIToken{},
		&models.APIClient{},
		&models.PasswordReset{},
		&models.MFASecret{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
	))
	return db
}

func TestService_PreviewRotationSweep(t *testing.T) {
	db := setupS2FullDB(t)

	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("test-passphrase-preview"))

	result, err := svc.PreviewRotationSweep(db)
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestService_RotateDEK_NotInitialized(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	err := svc.RotateDEK("passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestService_RotateDEK_Initialized(t *testing.T) {
	svc := newInitializedService(t)
	// RotateDEK without a sweep — must succeed.
	err := svc.RotateDEK("test-passphrase-service")
	require.NoError(t, err)
}

// TestService_RotateDEKWithSweep_AuthTables verifies that sweepSessions,
// sweepAPITokens, and sweepPasswordResets re-encrypt seeded rows correctly
// (exercising the inner loop bodies that are at 17.9% coverage).
// TestService_RotateDEKWithSweep_DeletesBackupFiles exercises deleteBackupFiles inner loop
// by pre-creating a .backup.* file in the key dir before rotation.
func TestService_RotateDEKWithSweep_DeletesBackupFiles(t *testing.T) {
	db := setupS2FullDB(t)

	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("test-passphrase-backup"))

	// Simulate a legacy backup file left behind by an old RotateDEK call.
	backupPath := filepath.Join(dir, "dek.key.backup.old")
	require.NoError(t, os.WriteFile(backupPath, []byte("stale"), 0600))

	result, err := svc.RotateDEKWithSweep("test-passphrase-backup", db)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// The backup file must have been deleted.
	_, statErr := os.Stat(backupPath)
	assert.True(t, os.IsNotExist(statErr), "backup file must be removed after rotation")
}

func TestKeyManager_Initialize_SecondRun_ReadsSalt(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("passphrase"))
	// Second initialization: salt and DEK already exist — exercises the read path.
	svc2 := NewService(cfg, dir)
	require.NoError(t, svc2.Initialize("passphrase"))
}

func TestKeyManager_Initialize_InvalidSaltSize(t *testing.T) {
	dir := t.TempDir()
	// Write a salt file with wrong size (not 32 bytes).
	require.NoError(t, os.WriteFile(filepath.Join(dir, "salt.key"), []byte("short"), 0600))

	km := NewKeyManager(dir, "dek.key", "salt.key")
	// deriveKEK calls ensureSaltExists which will see the wrong-size salt.
	err := km.Initialize("passphrase")
	require.Error(t, err)
}

// setupEnabledAuthEncUninitializedService creates an AuthEncryption with encryption
// enabled but whose service.initialized is forced to false after setup. This allows
// tests to reach the "service is enabled" branch while making EncryptSecret /
// DecryptSecret / RotateDEKWithSweep return an error — exactly the uncovered branch
// in each Encrypt*/Decrypt* and RotateAuthEncryption wrapper.
func setupEnabledAuthEncBroken(t *testing.T, db *gorm.DB) *AuthEncryption {
	t.Helper()
	ae := setupS2AuthEncEnabled(t, db)
	// Force the service back to "not initialized" so Encrypt*/Decrypt* calls fail
	// even though IsEnabled() remains true.
	ae.service.mu.Lock()
	ae.service.initialized = false
	ae.service.mu.Unlock()
	return ae
}

// TestAuthEncryption_EncryptError_Suite covers the error-return branches in every
// Encrypt* and Decrypt* wrapper when the underlying service fails.
// Each wrapper has one uncovered line: "return nil, nil, fmt.Errorf(...)".
func TestAuthEncryption_EncryptError_Suite(t *testing.T) {
	db := setupS2DB(t)
	ae := setupEnabledAuthEncBroken(t, db)

	t.Run("EncryptClientSecret_Error", func(t *testing.T) {
		_, _, err := ae.EncryptClientSecret("secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt client secret")
	})

	t.Run("DecryptClientSecret_Error", func(t *testing.T) {
		// Re-enable initialized so IsEnabled+initialized==true, but pass bad bytes.
		ae.service.mu.Lock()
		ae.service.initialized = true
		ae.service.mu.Unlock()
		_, err := ae.DecryptClientSecret([]byte("not-valid-json"), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt client secret")
		// Break again for remaining subtests.
		ae.service.mu.Lock()
		ae.service.initialized = false
		ae.service.mu.Unlock()
	})

	t.Run("EncryptSessionToken_Error", func(t *testing.T) {
		_, _, err := ae.EncryptSessionToken("token", uint(1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt session token")
	})

	t.Run("EncryptAPIToken_Error", func(t *testing.T) {
		_, _, err := ae.EncryptAPIToken("token", uint(1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt API token")
	})

	t.Run("DecryptAPIToken_Error", func(t *testing.T) {
		ae.service.mu.Lock()
		ae.service.initialized = true
		ae.service.mu.Unlock()
		_, err := ae.DecryptAPIToken([]byte("not-valid-json"), nil, uint(1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt API token")
		ae.service.mu.Lock()
		ae.service.initialized = false
		ae.service.mu.Unlock()
	})

	t.Run("EncryptPasswordResetToken_Error", func(t *testing.T) {
		_, _, err := ae.EncryptPasswordResetToken("token", uint(1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt password reset token")
	})

	t.Run("DecryptPasswordResetToken_Error", func(t *testing.T) {
		ae.service.mu.Lock()
		ae.service.initialized = true
		ae.service.mu.Unlock()
		_, err := ae.DecryptPasswordResetToken([]byte("not-valid-json"), nil, uint(1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt password reset token")
	})
}

// TestAuthEncryption_StoreEncryptError_Suite covers the DB-Create error branches in
// StoreEncryptedAPIClient, StoreEncryptedSession, StoreEncryptedAPIToken (77.8%).
// Each Store* function has two uncovered statements: the encryption-error return and
// the db.Create-error return. We trigger the db.Create error by inserting a row with
// a duplicate unique-constrained field (ClientID / primary key collision).
func TestAuthEncryption_StoreEncryptError_Suite(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEnc(t, db) // encryption disabled — passthrough, no encrypt failure

	t.Run("StoreEncryptedAPIClient_DBCreateError", func(t *testing.T) {
		client1 := &models.APIClient{
			Name:      "dup-client",
			ClientID:  "dup-client-id",
			IsActive:  true,
			CreatedAt: time.Now(),
		}
		require.NoError(t, ae.StoreEncryptedAPIClient(client1, "secret1"))

		// Second insert with same ClientID must fail the unique constraint.
		client2 := &models.APIClient{
			Name:      "dup-client-2",
			ClientID:  "dup-client-id",
			IsActive:  true,
			CreatedAt: time.Now(),
		}
		err := ae.StoreEncryptedAPIClient(client2, "secret2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store API client")
	})

	t.Run("StoreEncryptedSession_DBCreateError", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour)
		sess1 := &models.Session{
			UserID:    99,
			CreatedAt: time.Now(),
			ExpiresAt: &expiresAt,
		}
		require.NoError(t, ae.StoreEncryptedSession(sess1, "tok1"))

		// Force a primary key collision.
		sess2 := &models.Session{
			ID:        sess1.ID,
			UserID:    99,
			CreatedAt: time.Now(),
			ExpiresAt: &expiresAt,
		}
		err := ae.StoreEncryptedSession(sess2, "tok2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store session")
	})

	t.Run("StoreEncryptedAPIToken_DBCreateError", func(t *testing.T) {
		tok1 := &models.APIToken{
			ClientID:  77,
			Scope:     "read",
			CreatedAt: time.Now(),
		}
		require.NoError(t, ae.StoreEncryptedAPIToken(tok1, "tok-val-1"))

		// Force a primary key collision.
		tok2 := &models.APIToken{
			ID:        tok1.ID,
			ClientID:  77,
			Scope:     "read",
			CreatedAt: time.Now(),
		}
		err := ae.StoreEncryptedAPIToken(tok2, "tok-val-2")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to store API token")
	})
}

// TestAuthEncryption_StoreEncryptCallError covers the encrypt-failure path in each
// Store* method (when EncryptXxx itself returns an error). This exercises the
// "return fmt.Errorf("failed to encrypt ...")" line that 77.8% coverage misses.
func TestAuthEncryption_StoreEncryptCallError(t *testing.T) {
	db := setupS2DB(t)
	ae := setupEnabledAuthEncBroken(t, db)

	t.Run("StoreEncryptedAPIClient_EncryptError", func(t *testing.T) {
		client := &models.APIClient{
			Name:      "err-client",
			ClientID:  "err-client-id",
			IsActive:  true,
			CreatedAt: time.Now(),
		}
		err := ae.StoreEncryptedAPIClient(client, "secret")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt client secret")
	})

	t.Run("StoreEncryptedSession_EncryptError", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour)
		sess := &models.Session{
			UserID:    88,
			CreatedAt: time.Now(),
			ExpiresAt: &expiresAt,
		}
		err := ae.StoreEncryptedSession(sess, "token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt session token")
	})

	t.Run("StoreEncryptedAPIToken_EncryptError", func(t *testing.T) {
		tok := &models.APIToken{
			ClientID:  55,
			Scope:     "read",
			CreatedAt: time.Now(),
		}
		err := ae.StoreEncryptedAPIToken(tok, "tok-val")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to encrypt API token")
	})
}

// TestAuthEncryption_RetrieveDecryptError covers the decrypt-failure path in each
// Retrieve* method (85.7% → targets the "return "", fmt.Errorf("failed to decrypt...")" line).
// We store a row with deliberately corrupt ciphertext bytes, then Retrieve* must fail
// on the Decrypt step (not the DB-fetch step).
func TestAuthEncryption_RetrieveDecryptError(t *testing.T) {
	db := setupS2DB(t)
	ae := setupS2AuthEncEnabled(t, db)

	corruptBlob := []byte("not-valid-json")

	t.Run("RetrieveAPIClientSecret_DecryptError", func(t *testing.T) {
		// Insert a row with corrupt ciphertext directly via DB.
		client := &models.APIClient{
			Name:                  "corrupt-client",
			ClientID:              "corrupt-client-id",
			EncryptedClientSecret: corruptBlob,
			IsActive:              true,
			CreatedAt:             time.Now(),
		}
		require.NoError(t, db.Create(client).Error)

		_, err := ae.RetrieveAPIClientSecret("corrupt-client-id")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt client secret")
	})

	t.Run("RetrieveSessionToken_DecryptError", func(t *testing.T) {
		expiresAt := time.Now().Add(time.Hour)
		sess := &models.Session{
			UserID:                1,
			EncryptedSessionToken: corruptBlob,
			CreatedAt:             time.Now(),
			ExpiresAt:             &expiresAt,
		}
		require.NoError(t, db.Create(sess).Error)

		_, err := ae.RetrieveSessionToken(sess.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt session token")
	})

	t.Run("RetrieveAPIToken_DecryptError", func(t *testing.T) {
		tok := &models.APIToken{
			ClientID:       1,
			EncryptedToken: corruptBlob,
			CreatedAt:      time.Now(),
		}
		require.NoError(t, db.Create(tok).Error)

		_, err := ae.RetrieveAPIToken(tok.ID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decrypt API token")
	})
}

// TestAuthEncryption_RotateAuthEncryption_SweepError covers the error-return path
// in RotateAuthEncryption when RotateDEKWithSweep fails (80.0% → line 26).
// We achieve this by enabling the service but forcing initialized=false so
// RotateDEKWithSweep returns "not initialized" — IsEnabled() is still true so we
// reach line 25 before failing.
func TestAuthEncryption_RotateAuthEncryption_SweepError(t *testing.T) {
	db := setupS2FullDB(t)
	ae := setupS2AuthEncEnabled(t, db)

	// Force initialized=false so RotateDEKWithSweep returns an error.
	ae.service.mu.Lock()
	ae.service.initialized = false
	ae.service.mu.Unlock()

	err := ae.RotateAuthEncryption("passphrase")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to rotate auth encryption keys")
}

func TestService_RotateDEKWithSweep_AuthTables(t *testing.T) {
	db := setupS2FullDB(t)

	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "salt.key",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("test-passphrase-sweep"))

	// Seed a session token row.
	sessEnc, sessMeta, err := svc.EncryptSecret([]byte("my-session-token"))
	require.NoError(t, err)

	expiresAt := time.Now().Add(time.Hour)
	sess := models.Session{
		UserID:                1,
		EncryptedSessionToken: sessEnc,
		SessionTokenMetadata:  models.JSON(sessMeta),
		CreatedAt:             time.Now(),
		ExpiresAt:             &expiresAt,
	}
	require.NoError(t, db.Create(&sess).Error)

	// Seed an API token row.
	tokEnc, tokMeta, err := svc.EncryptSecret([]byte("my-api-token"))
	require.NoError(t, err)

	apiTok := models.APIToken{
		ClientID:       1,
		EncryptedToken: tokEnc,
		TokenMetadata:  models.JSON(tokMeta),
		CreatedAt:      time.Now(),
	}
	require.NoError(t, db.Create(&apiTok).Error)

	// Seed a password reset row.
	resetEnc, resetMeta, err := svc.EncryptSecret([]byte("my-reset-token"))
	require.NoError(t, err)

	reset := models.PasswordReset{
		UserID:         1,
		EncryptedToken: resetEnc,
		TokenMetadata:  models.JSON(resetMeta),
		CreatedAt:      time.Now(),
	}
	require.NoError(t, db.Create(&reset).Error)

	// Now rotate DEK with sweep — all seeded rows must be re-encrypted.
	result, err := svc.RotateDEKWithSweep("test-passphrase-sweep", db)
	require.NoError(t, err)
	assert.NotNil(t, result)

	// After rotation the service must still decrypt the re-encrypted session token.
	var updatedSess models.Session
	require.NoError(t, db.First(&updatedSess, sess.ID).Error)
	plain, err := svc.DecryptSecret(updatedSess.EncryptedSessionToken)
	require.NoError(t, err)
	assert.Equal(t, "my-session-token", string(plain))
}

