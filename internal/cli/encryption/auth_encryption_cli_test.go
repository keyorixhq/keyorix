package encryption

// auth_encryption_cli_test.go — regression coverage for #292:
//   - AuthEncryptionCmd must actually be wired into the command tree.
//   - migrate must clear the plaintext column once the encrypted value is written.
//   - validate must flag unmigrated (plaintext-only) rows instead of silently
//     printing an all-clear.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/store"
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

	// Sessions are intentionally NOT part of this migration/table set — see
	// runMigrateAuthData's comment in auth_encryption_migrate.go: session_token
	// stores a SHA-256 hash, never plaintext, so there is nothing for
	// migrateSessions (removed) to have migrated in the first place.

	token := &models.APIToken{ClientID: 1, Token: "plain-api-token"}
	require.NoError(t, db.Create(token).Error)

	reset := &models.PasswordReset{UserID: 1, Token: "plain-reset-token"}
	require.NoError(t, db.Create(reset).Error)

	require.NoError(t, migrateAPIClients(db, authEnc, false))
	require.NoError(t, migrateAPITokens(db, authEnc, false))
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	var gotClient models.APIClient
	require.NoError(t, db.First(&gotClient, client.ID).Error)
	require.Empty(t, gotClient.ClientSecret, "plaintext client_secret must be cleared after migration")
	require.NotEmpty(t, gotClient.EncryptedClientSecret)
	plain, err := authEnc.DecryptClientSecret(gotClient.EncryptedClientSecret, []byte(gotClient.ClientSecretMetadata))
	require.NoError(t, err)
	require.Equal(t, "plain-client-secret", plain)

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
	require.NoError(t, migrateAPITokens(db, authEnc, false))
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))
}

// TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision guards the
// NULL-not-empty-string choice: token columns carry a unique index, so
// clearing two rows to "" would collide on the second UPDATE. (Originally
// written against sessions; sessions were removed from this migration path
// since session_token is a hash, never plaintext — api_tokens exercises the
// identical unique-index-collision hazard.)
func TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	t1 := &models.APIToken{ClientID: 1, Token: "api-token-one"}
	t2 := &models.APIToken{ClientID: 2, Token: "api-token-two"}
	require.NoError(t, db.Create(t1).Error)
	require.NoError(t, db.Create(t2).Error)

	require.NoError(t, migrateAPITokens(db, authEnc, false))

	var got1, got2 models.APIToken
	require.NoError(t, db.First(&got1, t1.ID).Error)
	require.NoError(t, db.First(&got2, t2.ID).Error)
	require.Empty(t, got1.Token)
	require.Empty(t, got2.Token)
	require.NotEmpty(t, got1.EncryptedToken)
	require.NotEmpty(t, got2.EncryptedToken)
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

// TestMigrateAuthData_DoesNotCorruptLiveSessionLookup is the regression test
// for the HIGH-severity migrateSessions defect: sessions.session_token has
// NEVER stored a plaintext token. store.CreateSession (see
// internal/storage/store/local_auth.go's hashSessionToken) always writes the
// SHA-256 hash of the token, and store.GetSession looks a session up by
// recomputing that same hash and matching it against this column.
//
// A previous version of runMigrateAuthData ran every session through a
// migrateSessions helper that matched on "session_token != ''" — true for
// every live session, since the column always holds a hash — "encrypted" the
// hash value as if it were a real secret, and then set session_token to NULL
// in the same UPDATE. NULL landed on the exact column GetSession keys its
// WHERE clause on, so every live session silently and permanently became
// unfindable while the CLI reported success.
//
// This test creates a session through the real store.CreateSession path (so
// the row looks exactly like production data — a hash, not plaintext), runs
// the auth-encryption migration end to end, and asserts the session can still
// be looked up by its original plaintext token afterward.
func TestMigrateAuthData_DoesNotCorruptLiveSessionLookup(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)
	ls := store.NewLocalStorage(db)
	ctx := context.Background()

	const plaintextToken = "a-real-session-token-issued-at-login" //nolint:gosec // test fixture, not a credential
	created, err := ls.CreateSession(ctx, &models.Session{
		UserID:       7,
		SessionToken: plaintextToken,
	})
	require.NoError(t, err)
	require.NotZero(t, created.ID)

	// Sanity check on the premise the original bug got wrong: the stored row
	// must hold a hash, not the plaintext token.
	var stored models.Session
	require.NoError(t, db.First(&stored, created.ID).Error)
	require.NotEqual(t, plaintextToken, stored.SessionToken, "session_token must be a hash, not the plaintext token")
	require.NotEmpty(t, stored.SessionToken)

	// Seed one row in each table that the migration DOES act on, so this test
	// exercises a full, non-trivial migration pass rather than a no-op.
	require.NoError(t, db.Create(&models.APIClient{Name: "c", ClientID: "regress-client", ClientSecret: "plain-secret", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.APIToken{ClientID: 1, Token: "plain-api-token-regress"}).Error)
	require.NoError(t, db.Create(&models.PasswordReset{UserID: 7, Token: "plain-reset-regress"}).Error)

	require.NoError(t, migrateAPIClients(db, authEnc, false))
	require.NoError(t, migrateAPITokens(db, authEnc, false))
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	// The regression check: the session must still be findable by its original
	// plaintext token after a full migration pass — proving migrate no longer
	// touches session_token.
	got, err := ls.GetSession(ctx, plaintextToken)
	require.NoError(t, err, "session must still be findable by its token after migration — session_token must not have been nulled")
	require.Equal(t, created.ID, got.ID)

	// And validate must not flag the (correctly untouched, hash-only) session
	// as needing migration either.
	unmigratedAPIClients, err := validateAPIClients(db, authEnc, false)
	require.NoError(t, err)
	require.Zero(t, unmigratedAPIClients, "the migrated client should no longer be flagged")
}
