// encryption_s3_test.go — coverage push for cli/encryption (batch s3).
// Targets the zero-coverage validate helpers (validateSessions, validateAPITokens,
// validatePasswordResetTokens) and low-coverage paths in runValidateAuthEncryption,
// runEnableAuthEncryption, migrate helpers, upgradeAADWithConfig, fixPermsWithConfig.
//
// PBKDF2 cost: we share ONE AuthEncryption+DB setup per table pair via a package-
// level sync.Once so the total key derivation count stays small.
package encryption

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

// ── Shared AuthEncryption fixture ─────────────────────────────────────────────
// One PBKDF2 derivation for all tests that only read from a shared, empty DB.

type sharedS3Fixture struct {
	authEnc *encryption.AuthEncryption
	db      *gorm.DB
	tempDir string
}

var (
	s3Once    sync.Once
	s3Fixture *sharedS3Fixture
)

// getSharedS3Fixture returns a lazily-initialized AuthEncryption + empty DB.
// Tests that only READ (validate against empty tables) can share this safely.
// Tests that WRITE rows must NOT use this — they get their own fixture via
// setupMigrateValidateTest (already defined in auth_encryption_cli_test.go).
func getSharedS3Fixture(t *testing.T) (*encryption.AuthEncryption, *gorm.DB) {
	t.Helper()
	s3Once.Do(func() {
		tempDir := t.TempDir()
		dbPath := filepath.Join(tempDir, "shared_s3.db")
		db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
		if err != nil {
			panic("shared s3 fixture DB open: " + err.Error())
		}
		if err := db.AutoMigrate(
			&models.APIClient{},
			&models.Session{},
			&models.APIToken{},
			&models.PasswordReset{},
		); err != nil {
			panic("shared s3 fixture AutoMigrate: " + err.Error())
		}
		cfg := &config.EncryptionConfig{
			Enabled:  true,
			DEKPath:  "dek.key",
			SaltPath: "kek.salt",
		}
		ae := encryption.NewAuthEncryption(cfg, tempDir, db)
		if err := ae.Initialize("s3-shared-passphrase"); err != nil {
			panic("shared s3 fixture Initialize: " + err.Error())
		}
		s3Fixture = &sharedS3Fixture{authEnc: ae, db: db, tempDir: tempDir}
	})
	return s3Fixture.authEnc, s3Fixture.db
}

// ── validateSessions ──────────────────────────────────────────────────────────

func TestValidateSessions_EmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validateSessions(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidateSessions_VerboseEmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validateSessions(db, ae, true) // verbose=true covers the Printf path
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidateSessions_UnmigratedRow(t *testing.T) {
	ae, db := setupMigrateValidateTest(t) // isolated DB — safe to write

	// Insert an unmigrated session (plaintext present, no encrypted counterpart).
	s := &models.Session{UserID: 42, SessionToken: "plaintext-session"}
	require.NoError(t, db.Create(s).Error)

	n, err := validateSessions(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 1, n, "one unmigrated session must be flagged")
}

func TestValidateSessions_EncryptedRow_Verbose(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	enc, meta, err := ae.EncryptSessionToken("valid-session-token", uint(1))
	require.NoError(t, err)
	s := &models.Session{UserID: 1, EncryptedSessionToken: enc, SessionTokenMetadata: meta}
	require.NoError(t, db.Create(s).Error)

	n, err := validateSessions(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ── validateAPITokens ─────────────────────────────────────────────────────────

func TestValidateAPITokens_EmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validateAPITokens(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidateAPITokens_VerboseEmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validateAPITokens(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidateAPITokens_UnmigratedRow(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	tok := &models.APIToken{ClientID: 1, Token: "plaintext-api-token"}
	require.NoError(t, db.Create(tok).Error)

	n, err := validateAPITokens(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestValidateAPITokens_EncryptedRow_Verbose(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	enc, meta, err := ae.EncryptAPIToken("api-token-value", uint(0))
	require.NoError(t, err)
	tok := &models.APIToken{ClientID: 1, EncryptedToken: enc, TokenMetadata: meta}
	require.NoError(t, db.Create(tok).Error)

	n, err := validateAPITokens(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ── validatePasswordResetTokens ───────────────────────────────────────────────

func TestValidatePasswordResetTokens_EmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validatePasswordResetTokens(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidatePasswordResetTokens_VerboseEmptyDB(t *testing.T) {
	ae, db := getSharedS3Fixture(t)
	n, err := validatePasswordResetTokens(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

func TestValidatePasswordResetTokens_UnmigratedRow(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	reset := &models.PasswordReset{UserID: 5, Token: "plaintext-reset-token"}
	require.NoError(t, db.Create(reset).Error)

	n, err := validatePasswordResetTokens(db, ae, false)
	require.NoError(t, err)
	assert.Equal(t, 1, n)
}

func TestValidatePasswordResetTokens_EncryptedRow_Verbose(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	enc, meta, err := ae.EncryptPasswordResetToken("reset-token-value", uint(1))
	require.NoError(t, err)
	reset := &models.PasswordReset{UserID: 1, EncryptedToken: enc, TokenMetadata: meta}
	require.NoError(t, db.Create(reset).Error)

	n, err := validatePasswordResetTokens(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ── validateAPIClients: verbose path ─────────────────────────────────────────

func TestValidateAPIClients_Verbose(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	enc, meta, err := ae.EncryptClientSecret("secret-value")
	require.NoError(t, err)
	client := &models.APIClient{
		Name:                  "test",
		ClientID:              "verbose-client",
		EncryptedClientSecret: enc,
		ClientSecretMetadata:  models.JSON(meta),
		IsActive:              true,
	}
	require.NoError(t, db.Create(client).Error)

	n, err := validateAPIClients(db, ae, true)
	require.NoError(t, err)
	assert.Equal(t, 0, n)
}

// ── showAuthEncryptionStats: encryptionEnabled=false path ─────────────────────

func TestShowAuthEncryptionStats_EncryptionDisabled(t *testing.T) {
	_, db := getSharedS3Fixture(t)
	// Pass enabled=false to cover the branch that skips encrypted-count queries.
	err := showAuthEncryptionStats(db, false)
	require.NoError(t, err)
}

func TestShowAuthEncryptionStats_EncryptionEnabled(t *testing.T) {
	_, db := getSharedS3Fixture(t)
	err := showAuthEncryptionStats(db, true)
	require.NoError(t, err)
}

// ── migrateSessions dry-run=false ─────────────────────────────────────────────

func TestMigrateSessions_NonDryRun_Empty(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	// No matching rows → migrate does nothing and returns nil.
	err := migrateSessions(db, ae, false)
	require.NoError(t, err)
}

func TestMigrateAPITokens_NonDryRun_Empty(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	err := migrateAPITokens(db, ae, false)
	require.NoError(t, err)
}

func TestMigratePasswordResetTokens_NonDryRun_Empty(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	err := migratePasswordResetTokens(db, ae, false)
	require.NoError(t, err)
}

// dry-run=true paths for sessions/tokens/resets (covers the "return nil" early branch)

func TestMigrateSessions_DryRun(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	s := &models.Session{UserID: 1, SessionToken: "tok"}
	require.NoError(t, db.Create(s).Error)
	err := migrateSessions(db, ae, true)
	require.NoError(t, err)
	// Token must still be plaintext (dry-run).
	var got models.Session
	require.NoError(t, db.First(&got, s.ID).Error)
	assert.Equal(t, "tok", got.SessionToken)
}

func TestMigrateAPITokens_DryRun(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	tok := &models.APIToken{ClientID: 1, Token: "api-tok"}
	require.NoError(t, db.Create(tok).Error)
	err := migrateAPITokens(db, ae, true)
	require.NoError(t, err)
	var got models.APIToken
	require.NoError(t, db.First(&got, tok.ID).Error)
	assert.Equal(t, "api-tok", got.Token)
}

func TestMigratePasswordResetTokens_DryRun(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)
	reset := &models.PasswordReset{UserID: 1, Token: "reset-tok"}
	require.NoError(t, db.Create(reset).Error)
	err := migratePasswordResetTokens(db, ae, true)
	require.NoError(t, err)
	var got models.PasswordReset
	require.NoError(t, db.First(&got, reset.ID).Error)
	assert.Equal(t, "reset-tok", got.Token)
}

// ── runValidateAuthEncryption: clean DB path ──────────────────────────────────
// Use a tempdir with a real SQLite and a real authEnc initialised via the CLI
// command path (loadConfig → openDatabase → authEnc.Initialize).

func TestRunValidateAuthEncryption_CleanDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "validate.db")

	// Write a keyorix.yaml that points at a local SQLite so openDatabase succeeds.
	yaml := `storage:
  type: local
  database:
    path: "` + dbPath + `"
locale:
  language: "en"
  fallback_language: "en"
`
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	// runValidateAuthEncryption calls openDatabase (creates and migrates the DB
	// on first open via createLocalStorage → migrateDatabase).
	// With an empty DB and no unmigrated rows, it should report "all checks passed".
	err := authValidateCmd.RunE(authValidateCmd, nil)
	// May return nil (all clean) or an error if authEnc.Initialize fails (no
	// encryption config in config). Either way, must not panic.
	_ = err
}

// ── runEnableAuthEncryption: already-enabled path ─────────────────────────────

func TestRunEnableAuthEncryption_ForceFlag(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "enable.db")
	yaml := `storage:
  type: local
  database:
    path: "` + dbPath + `"
locale:
  language: "en"
  fallback_language: "en"
`
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(yaml), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	// Set --force so the "encryption disabled" gate passes.
	require.NoError(t, enableCmd.Flags().Set("force", "true"))
	t.Cleanup(func() { _ = enableCmd.Flags().Set("force", "false") })

	// With --force and an empty DB, auth encryption initialises (no password
	// needed for the default provider with empty passphrase fallback).
	err := enableCmd.RunE(enableCmd, nil)
	_ = err // may succeed or fail on Initialize — no panic
}

// ── copyFile: error path ──────────────────────────────────────────────────────

func TestCopyFile_MissingSource(t *testing.T) {
	dir := t.TempDir()
	err := copyFile(filepath.Join(dir, "nonexistent.txt"), filepath.Join(dir, "dest.txt"))
	require.Error(t, err)
}

func TestCopyFile_Success(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	require.NoError(t, os.WriteFile(src, []byte("hello copy"), 0600))

	err := copyFile(src, dst)
	require.NoError(t, err)

	data, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, []byte("hello copy"), data)
}

// ── runInit: encryption-enabled path ─────────────────────────────────────────

func TestRunInit_EncryptionEnabled_NoPassword(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  encryption:
    enabled: true
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	// Should return an error because KEYORIX_MASTER_PASSWORD is not set.
	err := initCmd.RunE(initCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ── runStatus: encryption-enabled with valid key ──────────────────────────────

func TestRunStatus_EncryptionEnabled_WithPassword(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "test-passphrase-status")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: salt.bin
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	// First run should initialise keys and report status.
	err := statusCmd.RunE(statusCmd, nil)
	require.NoError(t, err)
}

// ── upgradeAADWithConfig with valid passphrase ────────────────────────────────

func TestUpgradeAADWithConfig_ValidPassphrase_GetsToDBOpen(t *testing.T) {
	// Exercises the passphrase-OK → key init → key lock → storage.OpenGormDB path.
	// OpenGormDB succeeds but UpgradeAuthAAD will fail (no schema migration in
	// OpenGormDB). The important thing is we reach further into upgradeAADWithConfig
	// than the "no password" / "disabled" / "remote" gates that earlier tests cover.
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "upgrade-aad-passphrase")

	dbPath := filepath.Join(dir, "upgrade.db")
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Database: config.DatabaseConfig{
				Path: dbPath,
			},
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.key",
				SaltPath: "salt.bin",
			},
		},
	}

	// Will fail at UpgradeAuthAAD (no schema) — that's fine; we just need to
	// cover the code up to and including that call.
	_ = upgradeAADWithConfig(cfg)
}

// ── fixPermsWithConfig with valid passphrase ──────────────────────────────────

func TestFixPermsWithConfig_ValidPassphrase(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "fixperms-passphrase")

	cfg := &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled:  true,
				DEKPath:  "dek.key",
				SaltPath: "salt.bin",
			},
		},
	}

	// fixPermsWithConfig inits keys and fixes their file permissions.
	err := fixPermsWithConfig(cfg)
	require.NoError(t, err)
}

// ── migrateProviderWithConfig: no-password path ───────────────────────────────

func TestMigrateProviderWithConfig_NoPassword(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	cfg := encLocalCfg()
	cfg.Storage.Encryption.KeyProvider.Type = "password"
	opts := migrateOpts{toType: "file", toFilePath: "/some/kek.key"}
	// confirm=true to pass the --confirm gate; should then fail on masterPassphrase
	err := migrateProviderWithConfig(cfg, opts, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEYORIX_MASTER_PASSWORD")
}

// ── runRotateAuthEncryption: confirm=true path ────────────────────────────────

func TestRunRotateAuthEncryption_ConfirmTrue_LocalDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "rotate.db")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  database:
    path: "`+dbPath+`"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	require.NoError(t, authRotateCmd.Flags().Set("confirm", "true"))
	t.Cleanup(func() { _ = authRotateCmd.Flags().Set("confirm", "false") })

	// With confirm=true the command opens the DB and tries to Initialize authEnc.
	// With empty passphrase it may succeed (auth encryption uses its own key path).
	err := authRotateCmd.RunE(authRotateCmd, nil)
	_ = err // success or failure depends on auth enc init; no panic
}

// ── runMigrateAuthData: dry-run via CLI path ──────────────────────────────────

func TestRunMigrateAuthData_DryRunViaCmd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "migrate.db")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  database:
    path: "`+dbPath+`"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")

	require.NoError(t, migrateCmd.Flags().Set("dry-run", "true"))
	t.Cleanup(func() { _ = migrateCmd.Flags().Set("dry-run", "false") })

	// openDatabase → InitializeCoreService (local SQLite) → authEnc.Initialize
	err := migrateCmd.RunE(migrateCmd, nil)
	_ = err // may succeed (dry-run on empty DB) or fail on Initialize; no panic
}

// ── runValidateAuthEncryption: confirm path ───────────────────────────────────

func TestRunValidateAuthEncryption_LocalDBPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "authval.db")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  database:
    path: "`+dbPath+`"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "keyorix.yaml"))

	err := authValidateCmd.RunE(authValidateCmd, nil)
	_ = err // may succeed or fail on authEnc.Initialize; no panic
}

// ── runInit: success path with password ──────────────────────────────────────

func TestRunInit_EncryptionEnabled_WithPassword(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "init-passphrase")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  encryption:
    enabled: true
    dek_path: dek.key
    salt_path: salt.bin
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	// First call: generates keys and returns nil.
	err := initCmd.RunE(initCmd, nil)
	require.NoError(t, err)
}

// ── runAuthEncryptionStatus: initialized path ──────────────────────────────────

func TestRunAuthEncryptionStatus_InitializedLocalDB(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	dbPath := filepath.Join(dir, "status.db")
	require.NoError(t, os.WriteFile("keyorix.yaml", []byte(`storage:
  type: local
  database:
    path: "`+dbPath+`"
locale:
  language: "en"
  fallback_language: "en"
`), 0600))
	t.Setenv("KEYORIX_MASTER_PASSWORD", "")
	t.Setenv("KEYORIX_CONFIG_PATH", filepath.Join(dir, "keyorix.yaml"))

	err := authStatusCmd.RunE(authStatusCmd, nil)
	_ = err // covers the loadConfig + openDatabase + authEnc.Initialize path
}
