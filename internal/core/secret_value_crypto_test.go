package core

import (
	"bytes"
	"context"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/i18n"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
)

// newEncryptedCore builds a KeyorixCore backed by SQLite with an initialised
// secret-value encryptor wired, plus a seeded project/environment.
func newEncryptedCore(t *testing.T) (*KeyorixCore, uint, uint) {
	t.Helper()
	require.NoError(t, i18n.InitializeForTesting())
	t.Cleanup(i18n.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.Project{}, &models.Environment{}, &models.SecretNode{}, &models.SecretVersion{}, &models.SecretAccessSchedule{}))
	require.NoError(t, db.Create(&models.Project{ID: 1, Name: "p"}).Error)
	require.NoError(t, db.Create(&models.Environment{ID: 1, ProjectID: 1, Name: "e"}).Error)

	enc := encryption.NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, t.TempDir())
	require.NoError(t, enc.Initialize("test-passphrase"))

	c := NewKeyorixCore(store.NewLocalStorage(db))
	c.SetSecretValueEncryptor(enc)
	require.True(t, c.SecretValueEncryptionActive())
	return c, 1, 1
}

func mkCreateReq(projectID, envID uint, value string) *CreateSecretRequest {
	return &CreateSecretRequest{
		Name:          "sec-" + value,
		Value:         []byte(value),
		ProjectID:     projectID,
		EnvironmentID: envID,
		Type:          "password",
		CreatedBy:     "unit-test",
	}
}

// TestSecretValue_EncryptedRoundTrip proves a value created with encryption wired is
// ciphertext at rest and round-trips back to the original plaintext.
func TestSecretValue_EncryptedRoundTrip(t *testing.T) {
	c, projectID, envID := newEncryptedCore(t)
	ctx := context.Background()

	const plaintext = "s3cr3t-value-🔐"
	secret, err := c.CreateSecret(ctx, mkCreateReq(projectID, envID, plaintext))
	require.NoError(t, err)

	version, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
	require.NoError(t, err)
	assert.False(t, bytes.Equal(version.EncryptedValue, []byte(plaintext)), "must be ciphertext at rest")
	assert.Equal(t, metadataEncrypted, versionMetadataStatus(version.EncryptionMetadata), "metadata must mark the row encrypted")

	got, err := c.GetSecretValue(ctx, secret.ID)
	require.NoError(t, err)
	assert.Equal(t, plaintext, string(got))
}

// TestSecretValue_FailsClosedWithoutKey proves an encrypted row cannot be read as
// plaintext when no encryptor is available: decryptVersionValue must error, never
// hand back the raw ciphertext bytes.
func TestSecretValue_FailsClosedWithoutKey(t *testing.T) {
	c, projectID, envID := newEncryptedCore(t)
	ctx := context.Background()

	secret, err := c.CreateSecret(ctx, mkCreateReq(projectID, envID, "top-secret"))
	require.NoError(t, err)
	version, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
	require.NoError(t, err)

	// Drop the key (simulate a misconfigured restart) and attempt a read of the
	// still-encrypted row.
	c.SetSecretValueEncryptor(nil)
	_, err = c.decryptVersionValue(secret, version)
	require.Error(t, err, "reading an encrypted row without a key must fail closed")
	assert.NotContains(t, err.Error(), "top-secret")
}

// TestSecretValue_AADTransplantRejected proves the AAD binding (#94) stops a
// ciphertext blob copied onto a DIFFERENT secret's version from decrypting.
func TestSecretValue_AADTransplantRejected(t *testing.T) {
	c, projectID, envID := newEncryptedCore(t)
	ctx := context.Background()

	victim, err := c.CreateSecret(ctx, mkCreateReq(projectID, envID, "victim-value"))
	require.NoError(t, err)
	victimVersion, err := c.storage.GetLatestSecretVersion(ctx, victim.ID)
	require.NoError(t, err)

	// A second, distinct secret whose row we will graft the victim's ciphertext onto.
	attacker := &models.SecretNode{ID: 999, Name: "attacker", ProjectID: projectID, EnvironmentID: envID}
	transplanted := &models.SecretVersion{
		SecretNodeID:       attacker.ID,
		VersionNumber:      victimVersion.VersionNumber,
		EncryptedValue:     victimVersion.EncryptedValue,
		EncryptionMetadata: victimVersion.EncryptionMetadata,
	}

	_, err = c.decryptVersionValue(attacker, transplanted)
	require.Error(t, err, "a transplanted ciphertext must fail AAD authentication")
}

// TestSecretValue_PlaintextRowStillReadable proves the metadata-driven read returns a
// legacy/dev plaintext row (empty metadata) verbatim, even with an encryptor wired.
func TestSecretValue_PlaintextRowStillReadable(t *testing.T) {
	c, projectID, _ := newEncryptedCore(t)

	secret := &models.SecretNode{ID: 42, ProjectID: projectID}
	plaintextRow := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		VersionNumber:      1,
		EncryptedValue:     []byte("legacy-plaintext"),
		EncryptionMetadata: models.JSON("{}"),
	}
	got, err := c.decryptVersionValue(secret, plaintextRow)
	require.NoError(t, err)
	assert.Equal(t, "legacy-plaintext", string(got))
}

// TestSecretValue_MalformedMetadataFailsClosed proves that EncryptionMetadata which
// fails to parse as JSON at all (garbage/truncated bytes — e.g. from a corrupted
// column or inconsistent backup restore) is treated as ambiguous, not plaintext:
// decryptVersionValue must error rather than silently returning EncryptedValue as if
// it were the secret's real value.
func TestSecretValue_MalformedMetadataFailsClosed(t *testing.T) {
	c, projectID, _ := newEncryptedCore(t)

	secret := &models.SecretNode{ID: 43, ProjectID: projectID}
	corruptedRow := &models.SecretVersion{
		SecretNodeID:       secret.ID,
		VersionNumber:      1,
		EncryptedValue:     []byte("possibly-real-ciphertext-bytes"),
		EncryptionMetadata: models.JSON(`{not valid json`),
	}

	assert.Equal(t, metadataAmbiguous, versionMetadataStatus(corruptedRow.EncryptionMetadata))

	got, err := c.decryptVersionValue(secret, corruptedRow)
	require.Error(t, err, "unparseable metadata must fail closed, not be treated as plaintext")
	assert.Nil(t, got)
	assert.NotEqual(t, "possibly-real-ciphertext-bytes", string(got))
}

// TestSecretValue_MissingAlgorithmFailsClosed proves that well-formed JSON metadata
// which is NOT the confirmed-empty "{}" plaintext marker, but also carries no (or an
// empty) "algorithm" field, is treated as ambiguous rather than plaintext.
// decryptVersionValue must error instead of silently returning EncryptedValue.
func TestSecretValue_MissingAlgorithmFailsClosed(t *testing.T) {
	c, projectID, _ := newEncryptedCore(t)

	testCases := []struct {
		name string
		meta models.JSON
	}{
		{"empty algorithm field", models.JSON(`{"algorithm":""}`)},
		{"other fields, no algorithm", models.JSON(`{"nonce":"abc123"}`)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret := &models.SecretNode{ID: 44, ProjectID: projectID}
			row := &models.SecretVersion{
				SecretNodeID:       secret.ID,
				VersionNumber:      1,
				EncryptedValue:     []byte("possibly-real-ciphertext-bytes"),
				EncryptionMetadata: tc.meta,
			}

			assert.Equal(t, metadataAmbiguous, versionMetadataStatus(row.EncryptionMetadata))

			got, err := c.decryptVersionValue(secret, row)
			require.Error(t, err, "metadata with no usable algorithm must fail closed")
			assert.Nil(t, got)
		})
	}
}

// TestSecretValue_EmptyObjectMetadataIsPlaintext is the non-regression check for the
// intended plaintext marker: an exact "{}" object (the shape the current write path
// always produces when encryption is disabled) must still be classified as confirmed
// plaintext and returned verbatim.
func TestSecretValue_EmptyObjectMetadataIsPlaintext(t *testing.T) {
	assert.Equal(t, metadataPlaintext, versionMetadataStatus(models.JSON("{}")))
	assert.Equal(t, metadataPlaintext, versionMetadataStatus(nil))
	assert.Equal(t, metadataPlaintext, versionMetadataStatus(models.JSON("")))
}
