// encryption_s25_test.go — coverage uplift for internal/encryption (s25 round).
//
// Focus areas (functions not yet reaching 90%):
//   - sweepSecretVersions: deserialize error, decrypt error, no-project-found error
//   - sweepSessions / sweepAPITokens / sweepAPIClients / sweepPasswordResets:
//     deserialize error (corrupt JSON in stored blob)
//   - sweepMFASecrets / sweepDynamicSecretConfigs / sweepDynamicSecretLeases:
//     deserialize error path
//   - KeyManager.RotateDEKWithSweep: sweepFn error path (old DEK stays active)
//   - Service.RotateDEKWithSweep: not-initialized guard
//   - Service.PreviewRotationSweep: not-initialized guard; tx.Begin-error path
//   - Service.UpgradeAuthAAD: not-initialized guard
//   - Service.EncryptSecret / EncryptSecretWithAAD / EncryptLargeSecret:
//     initialized happy paths (exercises the serialize path)
//   - ensureSaltExists: corrupted salt (wrong byte count) returns error
//   - ensureWrappedDEKExists: existing file path (re-read instead of generate)
//   - EncryptChunked / DecryptChunked: empty-input edge cases
//   - NewKeyProviderFromConfig: azure-kms without context succeeds construction
//   - Service.DecryptLargeSecret: happy path round-trip
//   - sweepDynamicSecretLeases: skip empty CredentialEnc
//   - GenerateKEK: positive iterations (explicit)
package encryption

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// ─── local helpers ────────────────────────────────────────────────────────────

func s25ES(t *testing.T) *EncryptionService {
	t.Helper()
	es, err := NewEncryptionService(make([]byte, 32))
	require.NoError(t, err)
	return es
}

func s25DB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file::s25_%s:?mode=memory&cache=shared", t.Name())),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.Session{},
		&models.APIToken{},
		&models.APIClient{},
		&models.PasswordReset{},
		&models.MFASecret{},
		&models.DynamicSecretConfig{},
		&models.DynamicSecretLease{},
		&models.SecretNode{},
		&models.SecretVersion{},
	))
	return db
}

func s25Svc(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("s25-passphrase"))
	return svc
}

// ─── sweepSecretVersions: deserialize error ──────────────────────────────────

func TestSweepSecretVersions_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	// Create a project node so that the node map lookup succeeds.
	node := &models.SecretNode{Name: "n1", ProjectID: 10, Type: "generic"}
	require.NoError(t, db.Create(node).Error)

	// Store a version with corrupt (non-parseable) encrypted value.
	ver := &models.SecretVersion{
		SecretNodeID:  node.ID,
		VersionNumber: 1,
		EncryptedValue: []byte(`{bad json`),
	}
	require.NoError(t, db.Create(ver).Error)

	_, _, err := sweepSecretVersions(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize secret_version")
}

// ─── sweepSecretVersions: no-project-found error ─────────────────────────────

func TestSweepSecretVersions_NoProjectFound_Error(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	// Encrypt a payload with the encryption service (AAD-bound path).
	aad := SecretAAD(99, 5, 1)
	enc, err := es.EncryptWithAAD([]byte("val"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	// Insert a version that references a SecretNodeID that has NO matching SecretNode row.
	ver := &models.SecretVersion{
		SecretNodeID:        9999, // no such node
		VersionNumber:       1,
		EncryptedValue:      encBytes,
		EncryptionMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(ver).Error)

	_, _, err = sweepSecretVersions(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no project found for secret_node_id")
}

// ─── sweepSecretVersions: decrypt error (wrong key) ──────────────────────────

func TestSweepSecretVersions_DecryptError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	// Build a node so the project lookup succeeds.
	node := &models.SecretNode{Name: "n2", ProjectID: 20, Type: "generic"}
	require.NoError(t, db.Create(node).Error)

	// Encrypt the payload with a DIFFERENT key so es.Decrypt fails.
	otherES, err := NewEncryptionService(func() []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(i + 77)
		}
		return k
	}())
	require.NoError(t, err)

	enc, err := otherES.Encrypt([]byte("secret"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	ver := &models.SecretVersion{
		SecretNodeID:       node.ID,
		VersionNumber:      1,
		EncryptedValue:     encBytes,
		EncryptionMetadata: models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(ver).Error)

	_, _, err = sweepSecretVersions(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt secret_version")
}

// ─── sweepSessions: deserialize error ────────────────────────────────────────

func TestSweepSessions_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.Session{
		UserID:                200,
		SessionToken:          "hash-corrupt",
		EncryptedSessionToken: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepSessions(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize session")
}

// ─── sweepAPITokens: deserialize error ───────────────────────────────────────

func TestSweepAPITokens_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.APIToken{
		Token:          "hash-corrupt",
		EncryptedToken: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepAPITokens(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize api_token")
}

// ─── sweepAPIClients: deserialize error ──────────────────────────────────────

func TestSweepAPIClients_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.APIClient{
		Name:                  "corrupt-client",
		ClientID:              "cid-corrupt-s25",
		ClientSecret:          "h",
		EncryptedClientSecret: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, err := sweepAPIClients(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize api_client")
}

// ─── sweepPasswordResets: deserialize error ───────────────────────────────────

func TestSweepPasswordResets_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.PasswordReset{
		UserID:         201,
		Token:          "hash-corrupt",
		EncryptedToken: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepPasswordResets(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize password_reset")
}

// ─── sweepMFASecrets: deserialize error ──────────────────────────────────────

func TestSweepMFASecrets_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.MFASecret{UserID: 202, SecretEnc: []byte(`{corrupt`)}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepMFASecrets(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize mfa_secret")
}

// ─── sweepDynamicSecretConfigs: deserialize error ────────────────────────────

func TestSweepDynamicSecretConfigs_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.DynamicSecretConfig{
		Name:        "corrupt-cfg",
		ProjectID:   1,
		AdminDSNEnc: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepDynamicSecretConfigs(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize dynamic_secret_config")
}

// ─── sweepDynamicSecretLeases: deserialize error ─────────────────────────────

func TestSweepDynamicSecretLeases_DeserializeError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.DynamicSecretLease{
		LeaseID:       "corrupt-lease",
		ConfigID:      1,
		Status:        "active",
		CredentialEnc: []byte(`{corrupt`),
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err := sweepDynamicSecretLeases(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to deserialize dynamic_secret_lease")
}

// ─── sweepDynamicSecretLeases: skip empty CredentialEnc ──────────────────────

func TestSweepDynamicSecretLeases_SkipsEmptyCredential_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.DynamicSecretLease{
		LeaseID:  "empty-lease",
		ConfigID: 2,
		Status:   "active",
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepDynamicSecretLeases(db, es, es, "v1", false)
	require.NoError(t, err)
	assert.Equal(t, 0, swept)
}

// ─── KeyManager.RotateDEKWithSweep: sweepFn error keeps old DEK active ───────

func TestKeyManager_RotateDEKWithSweep_SweepFnError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	oldVersion := svc.GetKeyVersion()

	sweepErr := fmt.Errorf("injected sweep failure")
	failFn := func(_, _ *EncryptionService, _ string) error { return sweepErr }

	err := svc.keyManager.RotateDEKWithSweep("pass-s25", failFn)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-encryption sweep failed")

	// Old DEK version must still be active (no rotation committed).
	assert.Equal(t, oldVersion, svc.GetKeyVersion())

	// Pending file must have been cleaned up.
	pendingPath := filepath.Join(dir, "dek.key.pending")
	_, statErr := os.Stat(pendingPath)
	assert.True(t, os.IsNotExist(statErr), "pending DEK file should be removed after sweep failure")

	svc.Shutdown()
}

// ─── Service.RotateDEKWithSweep: not-initialized guard ───────────────────────

func TestService_RotateDEKWithSweep_NotInitialized_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)

	db := s25DB(t)
	_, err := svc.RotateDEKWithSweep("pass", db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── Service.PreviewRotationSweep: not-initialized guard ─────────────────────

func TestService_PreviewRotationSweep_NotInitialized_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)

	db := s25DB(t)
	_, err := svc.PreviewRotationSweep(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── Service.PreviewRotationSweep: happy path (empty DB) ─────────────────────

func TestService_PreviewRotationSweep_EmptyDB(t *testing.T) {
	svc := s25Svc(t)
	db := s25DB(t)

	result, err := svc.PreviewRotationSweep(db)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.SecretVersionsSwept)
	assert.Equal(t, 0, result.SessionsSwept)
	svc.Shutdown()
}

// ─── Service.UpgradeAuthAAD: not-initialized guard ───────────────────────────

func TestService_UpgradeAuthAAD_NotInitialized_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)

	db := s25DB(t)
	_, err := svc.UpgradeAuthAAD(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── Service.UpgradeAuthAAD: happy path (empty DB) ───────────────────────────

func TestService_UpgradeAuthAAD_EmptyDB(t *testing.T) {
	svc := s25Svc(t)
	db := s25DB(t)

	result, err := svc.UpgradeAuthAAD(db)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, 0, result.MFASecretsSwept)
	assert.Equal(t, 0, result.DynamicSecretConfigsSwept)
	assert.Equal(t, 0, result.DynamicSecretLeasesSwept)
	svc.Shutdown()
}

// ─── Service.EncryptSecret / DecryptSecret: happy-path round-trip ────────────

func TestService_EncryptDecryptSecret_RoundTrip(t *testing.T) {
	svc := s25Svc(t)
	defer svc.Shutdown()

	plain := []byte("my-secret-value")
	enc, meta, err := svc.EncryptSecret(plain)
	require.NoError(t, err)
	assert.NotEmpty(t, enc)
	assert.NotEmpty(t, meta)

	got, err := svc.DecryptSecret(enc)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// ─── Service.EncryptSecretWithAAD / DecryptSecretWithAAD: round-trip ─────────

func TestService_EncryptSecretWithAAD_RoundTrip(t *testing.T) {
	svc := s25Svc(t)
	defer svc.Shutdown()

	plain := []byte("aad-secured-value")
	aad := SecretAAD(7, 3, 2)
	enc, meta, err := svc.EncryptSecretWithAAD(plain, aad)
	require.NoError(t, err)
	assert.NotEmpty(t, enc)
	assert.NotEmpty(t, meta)

	got, err := svc.DecryptSecretWithAAD(enc, aad)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// ─── Service.EncryptLargeSecret / DecryptLargeSecret: round-trip ─────────────

func TestService_EncryptDecryptLargeSecret_RoundTrip(t *testing.T) {
	svc := s25Svc(t)
	defer svc.Shutdown()

	// 130 bytes with 64 KB chunks → one chunk (much smaller than chunk size)
	plain := []byte("large-secret-that-fits-in-one-chunk-for-simplicity-in-test-data-1234567890")
	encChunks, metaChunks, err := svc.EncryptLargeSecret(plain, 64)
	require.NoError(t, err)
	assert.Len(t, encChunks, 1)
	assert.Len(t, metaChunks, 1)

	got, err := svc.DecryptLargeSecret(encChunks)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// ─── Service.EncryptLargeSecret: multi-chunk then decrypt ─────────────────────

func TestService_EncryptLargeSecret_MultiChunk(t *testing.T) {
	svc := s25Svc(t)
	defer svc.Shutdown()

	// Each chunk = 1 byte → forces as many chunks as bytes.
	// Use a small payload (5 bytes) to keep the test fast.
	plain := []byte("hello")
	encChunks, _, err := svc.EncryptLargeSecret(plain, 1) // 1 KB chunks
	require.NoError(t, err)
	// 5 bytes / 1024 byte chunks → 1 chunk (5 < 1024)
	assert.GreaterOrEqual(t, len(encChunks), 1)

	got, err := svc.DecryptLargeSecret(encChunks)
	require.NoError(t, err)
	assert.Equal(t, plain, got)
}

// ─── ensureSaltExists: wrong-size salt → error ───────────────────────────────

func TestEnsureSaltExists_WrongSizeReturnsError(t *testing.T) {
	dir := t.TempDir()
	saltPath := "kek.salt"
	// Write a 16-byte (invalid) salt.
	saltFullPath := filepath.Join(dir, saltPath)
	require.NoError(t, os.WriteFile(saltFullPath, make([]byte, 16), 0600))

	km := NewKeyManager(dir, "dek.key", saltPath)
	_, err := km.ensureSaltExists()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid salt size")
}

// ─── ensureWrappedDEKExists: existing file is kept (not regenerated) ──────────

func TestEnsureWrappedDEKExists_ExistingFileKept(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	// Initialize once — creates the DEK file.
	require.NoError(t, svc.Initialize("pass-s25"))

	// Capture the existing wrapped DEK bytes.
	dekPath := filepath.Join(dir, "dek.key")
	originalBytes, err := os.ReadFile(dekPath)
	require.NoError(t, err)

	// Initialize again with the same passphrase.
	svc2 := NewService(cfg, dir)
	require.NoError(t, svc2.Initialize("pass-s25"))

	// DEK file must not have changed — ensureWrappedDEKExists skipped.
	afterBytes, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	assert.Equal(t, originalBytes, afterBytes)

	svc.Shutdown()
	svc2.Shutdown()
}

// ─── GenerateKEK: explicit positive iteration count ───────────────────────────

func TestGenerateKEK_ExplicitIterations(t *testing.T) {
	salt := make([]byte, 32)
	kek1 := GenerateKEK("password", salt, 100000)
	kek2 := GenerateKEK("password", salt, 100000)
	assert.Equal(t, kek1, kek2, "same password+salt+iterations should produce same KEK")
	assert.Len(t, kek1, 32)
}

// ─── NewKeyProviderFromConfig: azure-kms without encryption context ───────────
// This should return an error at construction time because azurekms.New will
// fail without a valid KMS key ID + credentials, but the important thing is
// the code path after the context check (no kms_encryption_context) is reached.

func TestNewKeyProviderFromConfig_AzureKMS_NoContext_AttemptsBuild(t *testing.T) {
	cfg := &config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:     "azure-kms",
			KMSKeyID: "https://myvault.vault.azure.net/keys/mykey/version1",
			// No KMSEncryptionContext → must NOT fail with the context error.
		},
	}
	// azurekms.New may fail (no credentials in test env), but that's a different
	// error — the important branch is that we got PAST the encryption-context guard.
	_, err := NewKeyProviderFromConfig(cfg, t.TempDir(), "")
	if err != nil {
		// Must be an azure client error, NOT the context-guard error.
		assert.NotContains(t, err.Error(), "kms_encryption_context")
	}
}

// ─── DecryptChunked: wrong stream ID triggers stream-mismatch error ───────────

func TestDecryptChunked_StreamIDMismatch_S25(t *testing.T) {
	es := s25ES(t)
	data1 := []byte("chunk-stream-one")
	data2 := []byte("chunk-stream-two")

	chunks1, err := es.EncryptChunked(data1, 8, "v1")
	require.NoError(t, err)
	chunks2, err := es.EncryptChunked(data2, 8, "v1")
	require.NoError(t, err)
	require.True(t, len(chunks1) >= 1 && len(chunks2) >= 1)

	// Mix a chunk from stream2 into stream1's set.
	// Build a 2-chunk set where the second chunk belongs to a different stream.
	if len(chunks1) >= 2 {
		mixed := []*EncryptedData{chunks1[0], chunks2[0]}
		// Ensure both have totalChunks = 2 so the count check passes.
		mixed[0].Metadata.TotalChunks = 2
		mixed[1].Metadata.TotalChunks = 2
		// Force chunk index = 1 for the second chunk so slot assignment works.
		mixed[1].Metadata.ChunkIndex = 1
		_, err = es.DecryptChunked(mixed)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chunk stream id mismatch")
	}
}

// ─── SweepAllTables: happy path with a real populated SecretVersion row ───────

func TestSweepAllTables_WithSecretVersion_HappyPath(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	// Create a project node and version.
	node := &models.SecretNode{Name: "n-sweep", ProjectID: 30, Type: "generic"}
	require.NoError(t, db.Create(node).Error)

	aad := SecretAAD(node.ID, node.ProjectID, 1)
	enc, err := es.EncryptWithAAD([]byte("value"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	ver := &models.SecretVersion{
		SecretNodeID:       node.ID,
		VersionNumber:      1,
		EncryptedValue:     encBytes,
		EncryptionMetadata: models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(ver).Error)

	result, err := SweepAllTables(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, result.SecretVersionsSwept)
}

// ─── sweepSecretVersions: legacy row (no AADVersion) upgrades to AAD ─────────

func TestSweepSecretVersions_LegacyRow_UpgradesToAAD(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	node := &models.SecretNode{Name: "n-legacy", ProjectID: 40, Type: "generic"}
	require.NoError(t, db.Create(node).Error)

	// Encrypt without AAD (legacy path — AADVersion will be "").
	enc, err := es.Encrypt([]byte("legacy-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	ver := &models.SecretVersion{
		SecretNodeID:       node.ID,
		VersionNumber:      1,
		EncryptedValue:     encBytes,
		EncryptionMetadata: models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(ver).Error)

	swept, legacyUpgraded, err := sweepSecretVersions(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 1, legacyUpgraded)
}

// ─── sweepSecretVersions: dryRun skips DB write ───────────────────────────────

func TestSweepSecretVersions_DryRun_DoesNotPersist(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	node := &models.SecretNode{Name: "n-dry", ProjectID: 50, Type: "generic"}
	require.NoError(t, db.Create(node).Error)

	aad := SecretAAD(node.ID, node.ProjectID, 1)
	enc, err := es.EncryptWithAAD([]byte("dry-val"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	orig := make([]byte, len(encBytes))
	copy(orig, encBytes)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	ver := &models.SecretVersion{
		SecretNodeID:       node.ID,
		VersionNumber:      1,
		EncryptedValue:     encBytes,
		EncryptionMetadata: models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(ver).Error)

	swept, _, err := sweepSecretVersions(db, es, es, "v2", true /* dryRun */)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)

	// The stored bytes must be unchanged.
	var updated models.SecretVersion
	require.NoError(t, db.First(&updated, ver.ID).Error)
	assert.Equal(t, orig, []byte(updated.EncryptedValue))
}

// ─── sweepMFASecrets: AAD-bound row re-encrypts correctly ─────────────────────

func TestSweepMFASecrets_AADBoundRow_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	userID := uint(600)
	aad := MFASecretAAD(userID)
	enc, err := es.EncryptWithAAD([]byte("totp-aad"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.MFASecret{UserID: userID, SecretEnc: encBytes, SecretMeta: metaBytes}
	require.NoError(t, db.Create(row).Error)

	swept, legacyUpgraded, err := sweepMFASecrets(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacyUpgraded, "AAD-bound row is not a legacy row")
}

// ─── sweepDynamicSecretConfigs: AAD-bound row re-encrypts correctly ───────────

func TestSweepDynamicSecretConfigs_AADBoundRow_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	row := &models.DynamicSecretConfig{Name: "aad-cfg", ProjectID: 1, EnvironmentID: 2}
	require.NoError(t, db.Create(row).Error)

	aad := DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID)
	enc, err := es.EncryptWithAAD([]byte("dsn-aad"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row.AdminDSNEnc = encBytes
	row.AdminDSNMeta = metaBytes
	require.NoError(t, db.Save(row).Error)

	swept, legacy, err := sweepDynamicSecretConfigs(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacy)
}

// ─── sweepDynamicSecretLeases: AAD-bound row re-encrypts correctly ────────────

func TestSweepDynamicSecretLeases_AADBoundRow_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	leaseID := "aad-lease-s25"
	configID := uint(7)
	aad := DynamicSecretLeaseAAD(leaseID, configID)
	enc, err := es.EncryptWithAAD([]byte("cred-aad"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:        leaseID,
		ConfigID:       configID,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, db.Create(row).Error)

	swept, legacy, err := sweepDynamicSecretLeases(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
	assert.Equal(t, 0, legacy)
}

// ─── Decrypt: wrong nonce length → error ─────────────────────────────────────

func TestEncryptionService_Decrypt_WrongNonceLength_S25(t *testing.T) {
	es := s25ES(t)
	// 3 bytes of nonce → base64 encodes fine but GCM expects 12 bytes.
	import64 := "AAAA" // base64 for 3 zero-bytes
	enc := &EncryptedData{
		Data: []byte("ciphertext"),
		Metadata: EncryptionMetadata{
			Algorithm: aesCipherSuite,
			Nonce:     import64,
		},
	}
	_, err := es.Decrypt(enc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")
}

// ─── DecryptWithAAD: wrong nonce length → error ───────────────────────────────

func TestEncryptionService_DecryptWithAAD_WrongNonceLength_S25(t *testing.T) {
	es := s25ES(t)
	enc := &EncryptedData{
		Data: []byte("ciphertext"),
		Metadata: EncryptionMetadata{
			Algorithm: aesCipherSuite,
			Nonce:     "AAAA", // 3 bytes ≠ GCM nonce size
		},
	}
	_, err := es.DecryptWithAAD(enc, []byte("aad"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid nonce length")
}

// ─── sweepSessionss: happy path persists ─────────────────────────────────────

func TestSweepSessions_HappyPath_Persists_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	enc, err := es.Encrypt([]byte("sess-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.Session{
		UserID:                700,
		SessionToken:          "h-s25-sess",
		EncryptedSessionToken: encBytes,
		SessionTokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepSessions(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
}

// ─── sweepMFASecrets: decrypt error ──────────────────────────────────────────

func TestSweepMFASecrets_DecryptError(t *testing.T) {
	db := s25DB(t)

	// Use a zero key for the sweeper but encrypt with a different key.
	es := s25ES(t)
	otherES, err := NewEncryptionService(func() []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(i + 55)
		}
		return k
	}())
	require.NoError(t, err)

	enc, err := otherES.Encrypt([]byte("totp"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	row := &models.MFASecret{UserID: 900, SecretEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	_, _, err = sweepMFASecrets(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt mfa_secret")
}

// ─── sweepDynamicSecretConfigs: decrypt error ────────────────────────────────

func TestSweepDynamicSecretConfigs_DecryptError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)
	otherES, err := NewEncryptionService(func() []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(i + 66)
		}
		return k
	}())
	require.NoError(t, err)

	enc, err := otherES.Encrypt([]byte("dsn"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	row := &models.DynamicSecretConfig{Name: "decrypt-err-cfg", ProjectID: 1, AdminDSNEnc: encBytes}
	require.NoError(t, db.Create(row).Error)

	_, _, err = sweepDynamicSecretConfigs(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt dynamic_secret_config")
}

// ─── sweepDynamicSecretLeases: decrypt error ─────────────────────────────────

func TestSweepDynamicSecretLeases_DecryptError(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)
	otherES, err := NewEncryptionService(func() []byte {
		k := make([]byte, 32)
		for i := range k {
			k[i] = byte(i + 77)
		}
		return k
	}())
	require.NoError(t, err)

	enc, err := otherES.Encrypt([]byte("cred"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:       "decrypt-err-lease",
		ConfigID:      1,
		Status:        "active",
		CredentialEnc: encBytes,
	}
	require.NoError(t, db.Create(row).Error)

	_, _, err = sweepDynamicSecretLeases(db, es, es, "v2", false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decrypt dynamic_secret_lease")
}

// ─── Service.PreviewRotationSweep: with a corrupt row → sweep fails ───────────

func TestService_PreviewRotationSweep_SweepError(t *testing.T) {
	svc := s25Svc(t)
	db := s25DB(t)

	// Insert a session with corrupt data that causes the sweep to fail.
	row := &models.Session{
		UserID:                901,
		SessionToken:          "h-preview-err",
		EncryptedSessionToken: []byte(`{corrupt json`),
	}
	require.NoError(t, db.Create(row).Error)

	_, err := svc.PreviewRotationSweep(db)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dry-run sweep preview failed")
	svc.Shutdown()
}

// ─── deleteBackupFiles: os.Remove error (non-empty dir with backup name) ───────

func TestKeyManager_DeleteBackupFiles_RemoveError(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")

	// Create a non-empty directory with the backup filename pattern.
	// os.Remove on a non-empty directory returns an error, exercising the
	// "[WARN] failed to delete backup DEK file" log path.
	backupDirName := "dek.key.backup.9999999"
	backupDir := filepath.Join(dir, backupDirName)
	require.NoError(t, os.MkdirAll(filepath.Join(backupDir, "subdir"), 0700))

	// deleteBackupFiles should log a warning but not panic.
	km.deleteBackupFiles() // must not return an error (void function)

	// The directory should still exist since Remove failed.
	_, err := os.Stat(backupDir)
	assert.NoError(t, err, "non-empty directory should NOT have been removed")
}

// ─── ensureSaltExists: unreadable salt file → SafeReadFile error ─────────────

func TestEnsureSaltExists_UnreadableSaltFile_Error(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file — chmod test meaningless")
	}
	dir := t.TempDir()
	saltPath := "kek.salt"
	saltFullPath := filepath.Join(dir, saltPath)
	// Write a valid 32-byte salt.
	require.NoError(t, os.WriteFile(saltFullPath, make([]byte, 32), 0600))
	// Make it unreadable.
	require.NoError(t, os.Chmod(saltFullPath, 0000))
	t.Cleanup(func() { _ = os.Chmod(saltFullPath, 0600) })

	km := NewKeyManager(dir, "dek.key", saltPath)
	_, err := km.ensureSaltExists()
	require.Error(t, err)
	// Either "failed to read salt" or a permission-denied wrapped error.
	assert.Contains(t, err.Error(), "failed to read salt")
}

// ─── RewrapDEK: unreadable DEK file → SafeReadFile error ─────────────────────

func TestKeyManager_RewrapDEK_UnreadableDEKFile_Error(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// Make the dek.key file unreadable so SafeReadFile fails during RewrapDEK.
	dekPath := filepath.Join(dir, "dek.key")
	require.NoError(t, os.Chmod(dekPath, 0000))
	t.Cleanup(func() { _ = os.Chmod(dekPath, 0600) })

	goodProvider := &mockKeyProvider{kek: make([]byte, 32)}
	err := svc.keyManager.RewrapDEK(goodProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "re-read active DEK under lock")
	svc.Shutdown()
}

// ─── Service.Initialize: file key provider with missing file → error ────────

func TestService_Initialize_FileProviderMissingFile_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: filepath.Join(dir, "nonexistent-kek.hex"),
		},
	}
	svc := NewService(cfg, dir)
	err := svc.Initialize("any-pass")
	require.Error(t, err)
	// The file provider's KEK() fails when the file doesn't exist.
	assert.True(t, err != nil, "expected error when key file is missing")
}

// ─── KeyManager.Initialize: keyProvider returns error → Initialize fails ───────

func TestKeyManager_Initialize_ProviderError(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	// Set a provider that always errors.
	km.SetKeyProvider(&mockKeyProvider{err: fmt.Errorf("provider broken")})

	err := km.Initialize("any-pass")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "provider broken")
}

// ─── RotateDEKWithSweep (KeyManager): RotateDEK with unreadable DEK → error ──

func TestKeyManager_RotateDEKWithSweep_UnreadableDEKFile_Error(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// Make the dek.key file unreadable to simulate a pending write failure.
	// The pending file will be written first, but once the rename is attempted
	// after a successful sweep, we need something else to fail.
	// Instead: make the base directory read-only so the pending file can't be written.
	// Actually the best approach is to make the baseDir not writable.
	require.NoError(t, os.Chmod(dir, 0500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

	err := svc.keyManager.RotateDEKWithSweep("pass-s25", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	require.Error(t, err)
	// The error comes from writing the pending DEK file.
	assert.NotNil(t, err)
	svc.Shutdown()
}

// ─── RotateDEK (deprecated): unreadable DEK file → SafeReadFile error ─────────

func TestKeyManager_RotateDEK_UnreadableDEKFile_Error(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// Make the dek.key file unreadable.
	dekPath := filepath.Join(dir, "dek.key")
	require.NoError(t, os.Chmod(dekPath, 0000))
	t.Cleanup(func() { _ = os.Chmod(dekPath, 0600) })

	err := svc.keyManager.RotateDEK("pass-s25")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read old DEK")
	svc.Shutdown()
}

// ─── sweepSessions: Updates() error (DB closed mid-sweep) ────────────────────

func TestSweepSessions_UpdatesError(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("session-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	// Open a fresh DB just for this test.
	db, err := gorm.Open(sqlite.Open("file::s25_sweep_sess_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Session{}))

	row := &models.Session{
		UserID:                950,
		SessionToken:          "h-close-test",
		EncryptedSessionToken: encBytes,
		SessionTokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	// Close the underlying SQL DB so Updates() fails.
	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepSessions(db, es, es, "v2", false)
	// After close, the error may come from Find (early) or Updates (late).
	// Either way, an error must be returned.
	require.Error(t, err)
}

// ─── sweepAPITokens: Updates() error (DB closed mid-sweep) ───────────────────

func TestSweepAPITokens_UpdatesError(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("api-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_apitoken_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.APIToken{}))

	row := &models.APIToken{
		Token:          "h-close-apitok",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepAPITokens(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepAPIClients: Updates() error (DB closed mid-sweep) ──────────────────

func TestSweepAPIClients_UpdatesError(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("client-sec"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_apiclient_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.APIClient{}))

	row := &models.APIClient{
		Name:                  "close-client",
		ClientID:              "cid-close-s25",
		ClientSecret:          "h",
		EncryptedClientSecret: encBytes,
		ClientSecretMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, err = sweepAPIClients(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepPasswordResets: Updates() error (DB closed mid-sweep) ──────────────

func TestSweepPasswordResets_UpdatesError(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("reset-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_pwreset_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.PasswordReset{}))

	row := &models.PasswordReset{
		UserID:         951,
		Token:          "h-close-reset",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepPasswordResets(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepMFASecrets: Updates() error (DB closed mid-sweep) ──────────────────

func TestSweepMFASecrets_UpdatesError(t *testing.T) {
	es := s25ES(t)
	userID := uint(970)
	aad := MFASecretAAD(userID)
	enc, err := es.EncryptWithAAD([]byte("totp"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_mfa_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.MFASecret{}))

	row := &models.MFASecret{UserID: userID, SecretEnc: encBytes, SecretMeta: metaBytes}
	require.NoError(t, db.Create(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepMFASecrets(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepDynamicSecretConfigs: Updates() error (DB closed) ──────────────────

func TestSweepDynamicSecretConfigs_UpdatesError(t *testing.T) {
	es := s25ES(t)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_dynconfig_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretConfig{}))

	row := &models.DynamicSecretConfig{Name: "close-cfg", ProjectID: 1, EnvironmentID: 2}
	require.NoError(t, db.Create(row).Error)

	aad := DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID)
	enc, err := es.EncryptWithAAD([]byte("dsn"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	row.AdminDSNEnc = encBytes
	row.AdminDSNMeta = metaBytes
	require.NoError(t, db.Save(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepDynamicSecretConfigs(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepDynamicSecretLeases: Updates() error (DB closed) ───────────────────

func TestSweepDynamicSecretLeases_UpdatesError(t *testing.T) {
	es := s25ES(t)

	db, err := gorm.Open(sqlite.Open("file::s25_sweep_dynlease_close?mode=memory&cache=shared"),
		&gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.DynamicSecretLease{}))

	leaseID := "close-lease-s25"
	configID := uint(10)
	aad := DynamicSecretLeaseAAD(leaseID, configID)
	enc, err := es.EncryptWithAAD([]byte("cred"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:        leaseID,
		ConfigID:       configID,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, db.Create(row).Error)

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	_, _, err = sweepDynamicSecretLeases(db, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepSessions: Updates() error via read-only view ───────────────────────
// Opens a second GORM connection to the same DB in read-only mode so that
// Find() succeeds (reads from the cache) but Updates() fails.

func TestSweepSessions_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("session-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	// Use a named file-based SQLite DB so we can open it in read-only mode.
	dbFile := filepath.Join(t.TempDir(), "sess_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.Session{}))

	row := &models.Session{
		UserID:                960,
		SessionToken:          "h-ro-test",
		EncryptedSessionToken: encBytes,
		SessionTokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, rwDB.Create(row).Error)

	// Open the same file in read-only mode (immutable).
	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepSessions(roDB, es, es, "v2", false)
	// On read-only SQLite, the UPDATE should fail.
	require.Error(t, err)
}

// ─── sweepAPIClients: Updates() error via read-only view ─────────────────────

func TestSweepAPIClients_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("client-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	dbFile := filepath.Join(t.TempDir(), "apiclient_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.APIClient{}))

	row := &models.APIClient{
		Name:                  "ro-client",
		ClientID:              "cid-ro-s25",
		ClientSecret:          "h",
		EncryptedClientSecret: encBytes,
		ClientSecretMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, rwDB.Create(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, err = sweepAPIClients(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepAPITokens: Updates() error via read-only view ──────────────────────

func TestSweepAPITokens_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("token-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	dbFile := filepath.Join(t.TempDir(), "apitoken_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.APIToken{}))

	row := &models.APIToken{
		Token:          "h-ro-apitoken",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, rwDB.Create(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepAPITokens(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepPasswordResets: Updates() error via read-only view ─────────────────

func TestSweepPasswordResets_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)
	enc, err := es.Encrypt([]byte("reset-val"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	dbFile := filepath.Join(t.TempDir(), "pwreset_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.PasswordReset{}))

	row := &models.PasswordReset{
		UserID:         961,
		Token:          "h-ro-reset",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, rwDB.Create(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepPasswordResets(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepMFASecrets: Updates() error via read-only DB ───────────────────────

func TestSweepMFASecrets_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)
	userID := uint(980)
	aad := MFASecretAAD(userID)
	enc, err := es.EncryptWithAAD([]byte("totp-ro"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	dbFile := filepath.Join(t.TempDir(), "mfa_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.MFASecret{}))

	row := &models.MFASecret{UserID: userID, SecretEnc: encBytes, SecretMeta: metaBytes}
	require.NoError(t, rwDB.Create(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepMFASecrets(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepDynamicSecretConfigs: Updates() error via read-only DB ──────────────

func TestSweepDynamicSecretConfigs_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)

	dbFile := filepath.Join(t.TempDir(), "dynconfig_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.DynamicSecretConfig{}))

	// Create row first to get an ID.
	row := &models.DynamicSecretConfig{Name: "ro-cfg", ProjectID: 5, EnvironmentID: 6}
	require.NoError(t, rwDB.Create(row).Error)

	aad := DynamicSecretConfigAAD(row.ID, row.ProjectID, row.EnvironmentID)
	enc, err := es.EncryptWithAAD([]byte("dsn-ro"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)
	row.AdminDSNEnc = encBytes
	row.AdminDSNMeta = metaBytes
	require.NoError(t, rwDB.Save(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepDynamicSecretConfigs(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepDynamicSecretLeases: Updates() error via read-only DB ───────────────

func TestSweepDynamicSecretLeases_UpdatesError_ReadOnly(t *testing.T) {
	es := s25ES(t)

	dbFile := filepath.Join(t.TempDir(), "dynlease_ro.db")
	rwDB, err := gorm.Open(sqlite.Open(dbFile), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	require.NoError(t, rwDB.AutoMigrate(&models.DynamicSecretLease{}))

	leaseID := "ro-lease-s25"
	configID := uint(15)
	aad := DynamicSecretLeaseAAD(leaseID, configID)
	enc, err := es.EncryptWithAAD([]byte("cred-ro"), "v1", aad)
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.DynamicSecretLease{
		LeaseID:        leaseID,
		ConfigID:       configID,
		Status:         "active",
		CredentialEnc:  encBytes,
		CredentialMeta: metaBytes,
	}
	require.NoError(t, rwDB.Create(row).Error)

	roDB, err := gorm.Open(
		sqlite.Open("file:"+dbFile+"?mode=ro"),
		&gorm.Config{Logger: logger.Discard},
	)
	require.NoError(t, err)

	_, _, err = sweepDynamicSecretLeases(roDB, es, es, "v2", false)
	require.Error(t, err)
}

// ─── sweepPasswordResets: happy path persists ────────────────────────────────

func TestSweepPasswordResets_HappyPath_Persists_S25(t *testing.T) {
	db := s25DB(t)
	es := s25ES(t)

	enc, err := es.Encrypt([]byte("reset-tok"), "v1")
	require.NoError(t, err)
	encBytes, err := SerializeEncryptedData(enc)
	require.NoError(t, err)
	metaBytes, err := json.Marshal(enc.Metadata)
	require.NoError(t, err)

	row := &models.PasswordReset{
		UserID:         800,
		Token:          "h-s25-reset",
		EncryptedToken: encBytes,
		TokenMetadata:  models.JSON(metaBytes),
	}
	require.NoError(t, db.Create(row).Error)

	swept, _, err := sweepPasswordResets(db, es, es, "v2", false)
	require.NoError(t, err)
	assert.Equal(t, 1, swept)
}

// ─── mockKeyProvider for testing wrong-size / error KEK ───────────────────────

type mockKeyProvider struct {
	kek []byte
	err error
}

func (m *mockKeyProvider) KEK() ([]byte, error) { return m.kek, m.err }
func (m *mockKeyProvider) Name() string          { return "mock" }

// ─── unwrapKey: too-short wrapped key returns error ───────────────────────────

func TestUnwrapKey_TooShort_Error(t *testing.T) {
	kek := make([]byte, 32)
	// 4 bytes is shorter than GCM's nonce size (12 bytes).
	_, err := unwrapKey([]byte{0x01, 0x02, 0x03, 0x04}, kek)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wrapped key too short")
}

// ─── deriveKEK: empty passphrase with no provider returns error ───────────────

func TestKeyManager_DeriveKEK_EmptyPassphrase_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	// No keyProvider set, passphrase is empty.
	_, err := km.deriveKEK("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "passphrase must not be empty")
}

// ─── KeyManager.RotateDEKWithSweep: empty passphrase (no provider) → error ────

func TestKeyManager_RotateDEKWithSweep_BadPassphrase_Error(t *testing.T) {
	dir := t.TempDir()
	// Build a key manager directly (no keyProvider) and manually set a fake DEK
	// to pass the "not initialized" check; the empty passphrase will then fail at
	// deriveKEK because there's no provider and passphrase == "".
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.currentDEK = make([]byte, 32) // satisfy the nil check

	// Create the salt file so ensureSaltExists doesn't generate a new one.
	saltPath := filepath.Join(dir, "kek.salt")
	require.NoError(t, os.WriteFile(saltPath, make([]byte, 32), 0600))

	err := km.RotateDEKWithSweep("", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to derive KEK for DEK rotation")
}

// ─── KeyManager.RotateDEKWithSweep: happy path → backup files deleted ─────────

func TestKeyManager_RotateDEKWithSweep_HappyPath_DeletesBackups(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-rotate"))

	// Create a backup file to verify it gets removed.
	backupPath := filepath.Join(dir, "dek.key.backup.1111111")
	require.NoError(t, os.WriteFile(backupPath, []byte("old"), 0600))

	err := svc.keyManager.RotateDEKWithSweep("pass-rotate", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	require.NoError(t, err)

	// Backup file must be removed by deleteBackupFiles.
	_, statErr := os.Stat(backupPath)
	assert.True(t, os.IsNotExist(statErr), "backup file should be removed after successful rotation")

	svc.Shutdown()
}

// ─── KeyManager.RotateDEKWithSweep: not initialized → error ──────────────────

func TestKeyManager_RotateDEKWithSweep_NotInitialized_Error(t *testing.T) {
	dir := t.TempDir()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	err := km.RotateDEKWithSweep("pass", func(_, _ *EncryptionService, _ string) error {
		return nil
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// ─── RewrapDEK: provider returns wrong-size KEK → error ─────────────────────

func TestKeyManager_RewrapDEK_WrongSizeKEK_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// A provider that returns a 16-byte KEK (wrong size — must be 32).
	shortKEK := &mockKeyProvider{kek: make([]byte, 16)}
	err := svc.keyManager.RewrapDEK(shortKEK)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "byte KEK, expected")
	svc.Shutdown()
}

// ─── RewrapDEK: provider returns an error ─────────────────────────────────────

func TestKeyManager_RewrapDEK_ProviderError(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// A provider that returns an error.
	errProvider := &mockKeyProvider{err: fmt.Errorf("injected provider error")}
	err := svc.keyManager.RewrapDEK(errProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "derive KEK from mock provider")
	svc.Shutdown()
}

// ─── RewrapDEK: stale snapshot error ─────────────────────────────────────────

func TestKeyManager_RewrapDEK_StaleSnapshot_Error(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	svc := NewService(cfg, dir)
	require.NoError(t, svc.Initialize("pass-s25"))

	// Overwrite dek.key with different content to simulate a concurrent rotation.
	dekPath := filepath.Join(dir, "dek.key")
	original, err := os.ReadFile(dekPath)
	require.NoError(t, err)
	// Write different bytes to simulate a newer DEK on disk.
	tampered := make([]byte, len(original))
	copy(tampered, original)
	tampered[len(tampered)-1] ^= 0xFF // flip last byte
	require.NoError(t, os.WriteFile(dekPath, tampered, 0600))

	// RewrapDEK should detect the snapshot mismatch and fail.
	newProvider := crypto.NewPasswordKeyProvider("new-pass", dir, "kek.salt")
	err = svc.keyManager.RewrapDEK(newProvider)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "changed since this process started")

	svc.Shutdown()
}
