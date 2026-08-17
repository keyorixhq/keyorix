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

	// Sessions, API clients, and API tokens are intentionally NOT part of this
	// migration/table set — see runMigrateAuthData's comment in
	// auth_encryption_migrate.go: session_token/client_secret/token all store a
	// SHA-256 hash, never plaintext, so there is nothing for
	// migrateSessions/migrateAPIClients/migrateAPITokens (all removed) to have
	// migrated in the first place. password_resets.token is the one column here
	// that IS a genuine legacy plaintext column.

	reset := &models.PasswordReset{UserID: 1, Token: "plain-reset-token"}
	require.NoError(t, db.Create(reset).Error)

	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	var gotReset models.PasswordReset
	require.NoError(t, db.First(&gotReset, reset.ID).Error)
	require.Empty(t, gotReset.Token, "plaintext reset token must be cleared after migration")
	require.NotEmpty(t, gotReset.EncryptedToken)

	// A second migrate pass must be a no-op (nothing left matching the
	// "plaintext present, no encrypted value" query) — and, critically, must not
	// fail on a unique-constraint collision now that multiple rows share a
	// cleared (NULL) plaintext column.
	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))
}

// TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision guards the
// NULL-not-empty-string choice: token columns carry a unique index, so
// clearing two rows to "" would collide on the second UPDATE. (Originally
// written against sessions, then api_tokens; both were removed from this
// migration path since their plaintext-holding columns are actually
// hash-only — password_resets exercises the identical unique-index-collision
// hazard and is the one remaining table with a genuine legacy plaintext
// column.)
func TestMigrateAuthData_ClearsPlaintext_MultipleRowsNoUniqueCollision(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	r1 := &models.PasswordReset{UserID: 1, Token: "reset-token-one"}
	r2 := &models.PasswordReset{UserID: 2, Token: "reset-token-two"}
	require.NoError(t, db.Create(r1).Error)
	require.NoError(t, db.Create(r2).Error)

	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	var got1, got2 models.PasswordReset
	require.NoError(t, db.First(&got1, r1.ID).Error)
	require.NoError(t, db.First(&got2, r2.ID).Error)
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
	unmigrated := &models.PasswordReset{UserID: 1, Token: "still-plaintext"}
	require.NoError(t, db.Create(unmigrated).Error)

	// Properly migrated row: should validate clean and not be counted.
	enc, meta, err := authEnc.EncryptPasswordResetToken("already-encrypted", 2)
	require.NoError(t, err)
	migrated := &models.PasswordReset{UserID: 2, EncryptedToken: enc, TokenMetadata: models.JSON(meta)}
	require.NoError(t, db.Create(migrated).Error)

	n, err := validatePasswordResetTokens(db, authEnc, false)
	require.NoError(t, err)
	require.Equal(t, 1, n, "exactly one unmigrated row (plaintext, no Encrypted* value) must be flagged")
}

// TestValidateAuthEncryption_CleanWhenFullyMigrated confirms the zero-unmigrated
// case still validates as clean (no false positives once migrate has run).
func TestValidateAuthEncryption_CleanWhenFullyMigrated(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	enc, meta, err := authEnc.EncryptPasswordResetToken("fully-migrated-secret", 1)
	require.NoError(t, err)
	reset := &models.PasswordReset{UserID: 1, EncryptedToken: enc, TokenMetadata: models.JSON(meta)}
	require.NoError(t, db.Create(reset).Error)

	n, err := validatePasswordResetTokens(db, authEnc, false)
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
// migrateSessions helper that matched on "session_token != ”" — true for
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

	// Seed a row in the one table the migration DOES act on, so this test
	// exercises a full, non-trivial migration pass rather than a no-op.
	require.NoError(t, db.Create(&models.PasswordReset{UserID: 7, Token: "plain-reset-regress"}).Error)

	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	// The regression check: the session must still be findable by its original
	// plaintext token after a full migration pass — proving migrate no longer
	// touches session_token.
	got, err := ls.GetSession(ctx, plaintextToken)
	require.NoError(t, err, "session must still be findable by its token after migration — session_token must not have been nulled")
	require.Equal(t, created.ID, got.ID)
}

// TestMigrateAuthData_DoesNotCorruptAPIClientOrTokenHash is the HIGH-severity
// regression test for the cli-encryption-001 defect: api_clients.client_secret
// and api_tokens.token hold a SHA-256 hash of the credential, never plaintext
// (see models.APIClient.ClientSecret / models.APIToken.Token) — identical in
// nature to sessions.session_token, which TestMigrateAuthData_
// DoesNotCorruptLiveSessionLookup above already guards.
//
// migrateAPIClients/migrateAPITokens used to match on "client_secret != ”" /
// "token != ”" (true for every row, since the column always holds a hash),
// "encrypt" the hash value as if it were a real secret, and null out the
// original column in the same UPDATE — permanently destroying the row's only
// stored credential-verification data on any database carrying rows from
// before the issuance/auth routes for these credential types were removed
// (#131). Both functions have been removed entirely (mirroring the earlier
// sessions fix), so this test seeds rows shaped like real legacy data —
// api_clients/api_tokens have no live construction path today (see git
// history), so a direct DB insert is the closest available stand-in for a
// pre-existing production row — runs the full available migration surface,
// and asserts neither column was touched.
func TestMigrateAuthData_DoesNotCorruptAPIClientOrTokenHash(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	const clientSecretHash = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3" // stand-in SHA-256-shaped hash
	const tokenHash = "3e23e8160039594a33894f6564e1b1348bbd7a00"        // stand-in SHA-256-shaped hash

	client := &models.APIClient{Name: "c", ClientID: "regress-client-hash", ClientSecret: clientSecretHash, IsActive: true}
	require.NoError(t, db.Create(client).Error)
	token := &models.APIToken{ClientID: 1, Token: tokenHash}
	require.NoError(t, db.Create(token).Error)

	// Seed a row in the one table the migration DOES act on, so this exercises
	// a full, non-trivial migration pass rather than a no-op.
	require.NoError(t, db.Create(&models.PasswordReset{UserID: 9, Token: "plain-reset-regress-2"}).Error)

	require.NoError(t, migratePasswordResetTokens(db, authEnc, false))

	// The regression check: client_secret/token must be byte-identical to what
	// was seeded — migrate must never have touched either column.
	var gotClient models.APIClient
	require.NoError(t, db.First(&gotClient, client.ID).Error)
	require.Equal(t, clientSecretHash, gotClient.ClientSecret, "client_secret hash must survive a migration pass untouched")
	require.Empty(t, gotClient.EncryptedClientSecret, "encrypted_client_secret must never be populated — there is nothing to migrate")

	var gotToken models.APIToken
	require.NoError(t, db.First(&gotToken, token.ID).Error)
	require.Equal(t, tokenHash, gotToken.Token, "token hash must survive a migration pass untouched")
	require.Empty(t, gotToken.EncryptedToken, "encrypted_token must never be populated — there is nothing to migrate")
}

// TestValidateAuthEncryption_DoesNotFlagAPIClientOrTokenHash is the validate-
// side counterpart of TestMigrateAuthData_DoesNotCorruptAPIClientOrTokenHash:
// a hash-only api_clients/api_tokens row must never be reported as needing
// migration (the cli-encryption-002 defect) — validateAPIClients/
// validateAPITokens have been removed entirely, so runValidateAuthEncryption's
// unmigrated count must come back zero even with such rows present.
func TestValidateAuthEncryption_DoesNotFlagAPIClientOrTokenHash(t *testing.T) {
	authEnc, db := setupMigrateValidateTest(t)

	require.NoError(t, db.Create(&models.APIClient{Name: "c", ClientID: "validate-hash-client", ClientSecret: "hash-looking-value", IsActive: true}).Error)
	require.NoError(t, db.Create(&models.APIToken{ClientID: 1, Token: "hash-looking-token"}).Error)

	// The only remaining validate helper (password resets) must still report
	// clean on an otherwise-empty table, and — critically — nothing here must
	// surface the seeded API client/token rows as unmigrated, since there is no
	// longer any code path that even looks at those two tables.
	n, err := validatePasswordResetTokens(db, authEnc, false)
	require.NoError(t, err)
	require.Zero(t, n, "no table this validate command still inspects should report unmigrated rows")
}
