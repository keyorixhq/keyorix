package encryption

// auth_encryption_cli_test.go — regression coverage for #292:
//   - AuthEncryptionCmd must actually be wired into the command tree.
//   - migrate must clear the plaintext column once the encrypted value is written.
//   - validate must flag unmigrated (plaintext-only) rows instead of silently
//     printing an all-clear.

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// TestAuthEncryptionCmd_WiredIntoCommandTree is the regression test for the
// core #292 defect: AuthEncryptionCmd was defined but never added to
// EncryptionCmd, so `keyorix encryption auth-encryption` (and every subcommand
// under it) failed with "unknown command" even though the code existed.
func TestAuthEncryptionCmd_WiredIntoCommandTree(t *testing.T) {
	found := false
	var names []string
	for _, cmd := range EncryptionCmd.Commands() {
		names = append(names, cmd.Name())
		if cmd.Name() == "auth-encryption" {
			found = true
		}
	}
	if !found {
		t.Fatalf("auth-encryption not found under EncryptionCmd; got subcommands: %v", names)
	}

	// The five documented subcommands must all be reachable too.
	want := map[string]bool{"status": false, "enable": false, "rotate": false, "migrate": false, "validate": false}
	for _, cmd := range AuthEncryptionCmd.Commands() {
		if _, ok := want[cmd.Name()]; ok {
			want[cmd.Name()] = true
		}
	}
	for name, ok := range want {
		if !ok {
			t.Errorf("auth-encryption subcommand %q not registered", name)
		}
	}
}

// setupMigrateValidateTest opens a real on-disk sqlite DB with encryption
// enabled (key files generated under t.TempDir()) and returns the AuthEncryption
// handle plus the raw *gorm.DB, mirroring how the CLI commands construct both.
func setupMigrateValidateTest(t *testing.T) (*encryption.AuthEncryption, *gorm.DB) {
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
	authEnc := encryption.NewAuthEncryption(cfg, tempDir, db)
	require.NoError(t, authEnc.Initialize("migrate-validate-test-passphrase"))

	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})

	return authEnc, db
}

// TestMigrateAuthData_ClearsPlaintextColumns is the regression test for latent
// defect #1: a successful migrate must null out the plaintext column, not just
// write the encrypted counterpart alongside it.
func TestMigrateAuthData_ClearsPlaintextColumns(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	client := &models.APIClient{Name: "c", ClientID: "client-1", ClientSecret: "plain-client-secret", IsActive: true}
	require.NoError(t, db.Create(client).Error)

	session := &models.Session{UserID: 1, SessionToken: "plain-session-token"}
	require.NoError(t, db.Create(session).Error)

	token := &models.APIToken{ClientID: 1, Token: "plain-api-token"}
	require.NoError(t, db.Create(token).Error)

	reset := &models.PasswordReset{UserID: 1, Token: "plain-reset-token"}
	require.NoError(t, db.Create(reset).Error)

	require.NoError(t, migrateAPIClients(db, authEnc, false))
	require.NoError(t, migrateSessions(db, authEnc, false))
	require.NoError(t, migrateAPITokens(db, authEnc, false))
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	var gotClient models.APIClient
	require.NoError(t, db.First(&gotClient, client.ID).Error)
	require.Empty(t, gotClient.ClientSecret, "plaintext client_secret must be cleared after migration")
	require.NotEmpty(t, gotClient.EncryptedClientSecret)
	plain, err := authEnc.DecryptClientSecret(gotClient.EncryptedClientSecret, []byte(gotClient.ClientSecretMetadata))
	require.NoError(t, err)
	require.Equal(t, "plain-client-secret", plain)

	var gotSession models.Session
	require.NoError(t, db.First(&gotSession, session.ID).Error)
	require.Empty(t, gotSession.SessionToken, "plaintext session_token must be cleared after migration")
	require.NotEmpty(t, gotSession.EncryptedSessionToken)

	var gotToken models.APIToken
	require.NoError(t, db.First(&gotToken, token.ID).Error)
	require.Empty(t, gotToken.Token, "plaintext token must be cleared after migration")
	require.NotEmpty(t, gotToken.EncryptedToken)

	var gotReset models.PasswordReset
	require.NoError(t, db.First(&gotReset, reset.ID).Error)
	require.Empty(t, gotReset.Token, "plaintext reset token must be cleared after migration")
	require.NotEmpty(t, gotReset.EncryptedToken)

	// A second migrate pass must be a no-op (nothing left matching the
	// "plaintext present, no encrypted value" query) — and, critically, must not
	// fail on a unique-constraint collision now that multiple rows share a
	// cleared (NULL) plaintext column.
	require.NoError(t, migrateAPIClients(db, authEnc, false))
	require.NoError(t, migrateSessions(db, authEnc, false))
	require.NoError(t, migrateAPITokens(db, authEnc, false))
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))
}

// TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision guards the
// NULL-not-empty-string choice: session_token/token columns carry a unique
// index, so clearing two rows to "" would collide on the second UPDATE.
func TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	s1 := &models.Session{UserID: 1, SessionToken: "session-token-one"}
	s2 := &models.Session{UserID: 2, SessionToken: "session-token-two"}
	require.NoError(t, db.Create(s1).Error)
	require.NoError(t, db.Create(s2).Error)

	require.NoError(t, migrateSessions(db, authEnc, false))

	var got1, got2 models.Session
	require.NoError(t, db.First(&got1, s1.ID).Error)
	require.NoError(t, db.First(&got2, s2.ID).Error)
	require.Empty(t, got1.SessionToken)
	require.Empty(t, got2.SessionToken)
	require.NotEmpty(t, got1.EncryptedSessionToken)
	require.NotEmpty(t, got2.EncryptedSessionToken)
}

// TestValidateAuthEncryption_FlagsUnmigratedRows is the regression test for
// latent defect #3: an unmigrated (plaintext-only, no Encrypted* value) row
// must be reported, not silently invisible to validate.
func TestValidateAuthEncryption_FlagsUnmigratedRows(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	// Unmigrated row: plaintext present, no Encrypted* value at all.
	unmigrated := &models.APIClient{Name: "u", ClientID: "unmigrated", ClientSecret: "still-plaintext", IsActive: true}
	require.NoError(t, db.Create(unmigrated).Error)

	// Properly migrated row: should validate clean and not be counted.
	enc, meta, err := authEnc.EncryptClientSecret("already-encrypted")
	require.NoError(t, err)
	migrated := &models.APIClient{Name: "m", ClientID: "migrated", EncryptedClientSecret: enc, ClientSecretMetadata: models.JSON(meta), IsActive: true}
	require.NoError(t, db.Create(migrated).Error)

	n, err := validateAPIClients(db, authEnc, false)
	require.NoError(t, err)
	require.Equal(t, 1, n, "exactly one unmigrated row (plaintext, no Encrypted* value) must be flagged")
}

// TestValidateAuthEncryption_CleanWhenFullyMigrated confirms the zero-unmigrated
// case still validates as clean (no false positives once migrate has run).
func TestValidateAuthEncryption_CleanWhenFullyMigrated(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	enc, meta, err := authEnc.EncryptClientSecret("fully-migrated-secret")
	require.NoError(t, err)
	client := &models.APIClient{Name: "m", ClientID: "clean", EncryptedClientSecret: enc, ClientSecretMetadata: models.JSON(meta), IsActive: true}
	require.NoError(t, db.Create(client).Error)

	n, err := validateAPIClients(db, authEnc, false)
	require.NoError(t, err)
	require.Zero(t, n)
}
