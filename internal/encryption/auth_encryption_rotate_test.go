package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupEnabledAuthEncryptionTest is like setupAuthEncryptionTest but with real
// encryption ENABLED (key files generated on disk), needed to exercise
// RotateAuthEncryption — with encryption disabled, EncryptClientSecret etc. are
// no-ops and there is nothing to rotate.
func setupEnabledAuthEncryptionTest(t *testing.T) (*AuthEncryption, *gorm.DB) {
	t.Helper()
	tempDir := t.TempDir()

	dbPath := filepath.Join(tempDir, "test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(
		&models.APIClient{},
		&models.Session{},
		&models.APIToken{},
		&models.PasswordReset{},
	))

	cfg := &config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	authEnc := NewAuthEncryption(cfg, tempDir, db)
	require.NoError(t, authEnc.Initialize("rotate-test-passphrase-correct-horse"))

	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
		_ = os.RemoveAll(tempDir)
	})

	return authEnc, db
}

// TestRotateAuthEncryption_SkipsUnmigratedRows verifies that a row with no
// Encrypted* value (an unmigrated, #278-affected plaintext-only row) does not
// abort the rotation loop — it is skipped, and every properly-encrypted row
// still rotates successfully.
func TestRotateAuthEncryption_SkipsUnmigratedRows(t *testing.T) {
	authEnc, db := setupEnabledAuthEncryptionTest(t)

	// Unmigrated row: plaintext-only, no Encrypted* value at all. Before the fix,
	// RotateAuthEncryption would call DecryptClientSecret on the empty
	// EncryptedClientSecret and abort the whole rotation with an error.
	unmigrated := &models.APIClient{Name: "unmigrated", ClientID: "unmigrated-client", ClientSecret: "plain-secret-never-encrypted", IsActive: true}
	require.NoError(t, db.Create(unmigrated).Error)

	// Properly-migrated row: has an Encrypted* value, should rotate cleanly.
	enc, meta, err := authEnc.EncryptClientSecret("secret-to-rotate")
	require.NoError(t, err)
	migrated := &models.APIClient{Name: "migrated", ClientID: "migrated-client", EncryptedClientSecret: enc, ClientSecretMetadata: models.JSON(meta), IsActive: true}
	require.NoError(t, db.Create(migrated).Error)

	require.NoError(t, authEnc.RotateAuthEncryption())

	// Unmigrated row untouched — still no Encrypted* value, plaintext intact.
	var gotUnmigrated models.APIClient
	require.NoError(t, db.Where("client_id = ?", "unmigrated-client").First(&gotUnmigrated).Error)
	require.Empty(t, gotUnmigrated.EncryptedClientSecret)
	require.Equal(t, "plain-secret-never-encrypted", gotUnmigrated.ClientSecret)

	// Migrated row rotated: still decrypts to the same plaintext.
	var gotMigrated models.APIClient
	require.NoError(t, db.Where("client_id = ?", "migrated-client").First(&gotMigrated).Error)
	plain, err := authEnc.DecryptClientSecret(gotMigrated.EncryptedClientSecret, []byte(gotMigrated.ClientSecretMetadata))
	require.NoError(t, err)
	require.Equal(t, "secret-to-rotate", plain)
}

// TestRotateAuthEncryption_RollsBackOnError verifies that a mid-loop failure
// rolls back the entire rotation transaction — no row is left partially
// rotated (some under the new key, the rest under the old one).
func TestRotateAuthEncryption_RollsBackOnError(t *testing.T) {
	authEnc, db := setupEnabledAuthEncryptionTest(t)

	// A row that rotates fine on its own — api_clients rotate before sessions, so
	// this row's re-encryption would already have been written to the DB by the
	// time the session below fails, if rotation weren't transactional.
	enc, meta, err := authEnc.EncryptClientSecret("secret-should-not-change")
	require.NoError(t, err)
	client := &models.APIClient{Name: "rollback-client", ClientID: "rollback-client-id", EncryptedClientSecret: enc, ClientSecretMetadata: models.JSON(meta), IsActive: true}
	require.NoError(t, db.Create(client).Error)
	originalCiphertext := append([]byte(nil), client.EncryptedClientSecret...)

	// A corrupt session row: EncryptedSessionToken is not valid serialized
	// encrypted data, so decrypting it during rotation fails deterministically.
	badSession := &models.Session{UserID: 1, EncryptedSessionToken: []byte("not-a-valid-encrypted-blob"), SessionTokenMetadata: models.JSON(`{}`)}
	require.NoError(t, db.Create(badSession).Error)

	err = authEnc.RotateAuthEncryption()
	require.Error(t, err)

	// Roll back means the earlier, individually-successful client re-encryption
	// must NOT have been persisted either.
	var gotClient models.APIClient
	require.NoError(t, db.Where("client_id = ?", "rollback-client-id").First(&gotClient).Error)
	require.Equal(t, originalCiphertext, gotClient.EncryptedClientSecret, "rotation must roll back ALL writes, not just the failing row, on mid-loop error")
}

// TestRotateAuthEncryption_RotatesPasswordResetTokens verifies rotate covers
// password reset tokens too — RotateAuthEncryption's doc/CLI help text claims
// to re-encrypt "all" authentication data, and migrate/validate already cover
// this table, so rotate must not silently skip it (#292).
func TestRotateAuthEncryption_RotatesPasswordResetTokens(t *testing.T) {
	authEnc, db := setupEnabledAuthEncryptionTest(t)

	enc, meta, err := authEnc.EncryptPasswordResetToken("reset-token-to-rotate")
	require.NoError(t, err)
	reset := &models.PasswordReset{UserID: 1, EncryptedToken: enc, TokenMetadata: models.JSON(meta)}
	require.NoError(t, db.Create(reset).Error)

	require.NoError(t, authEnc.RotateAuthEncryption())

	var got models.PasswordReset
	require.NoError(t, db.First(&got, reset.ID).Error)
	plain, err := authEnc.DecryptPasswordResetToken(got.EncryptedToken, []byte(got.TokenMetadata))
	require.NoError(t, err)
	require.Equal(t, "reset-token-to-rotate", plain)
}
