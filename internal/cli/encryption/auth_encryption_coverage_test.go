// auth_encryption_coverage_test.go — coverage uplift for narrow error
// branches in auth_encryption.go / auth_encryption_migrate.go /
// auth_encryption_validate.go that the existing test suite (encryption_s2/
// s22/s23/s27_test.go, g62_auth_encryption_lock_test.go) doesn't reach:
//
//   - openDatabase failures (unsupported storage type), reached through
//     authStatusWithConfig and enableAuthEncryptionWithConfig directly.
//   - config.Load failure through the runEnableAuthEncryption cobra shim.
//   - authEnc.Initialize failures caused by a wrong master passphrase against
//     already-provisioned key material, reached through runRotateAuthEncryption,
//     migrateAuthDataWithConfig, and validateAuthEncryptionWithConfig.
//   - the openDatabase failure through runRotateAuthEncryption's cobra shim.
package encryption

import (
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/keyorixhq/keyorix/internal/storage/sqlitedialect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// badStorageCfg returns a *config.Config with an unsupported storage type, so
// openDatabase(cfg) (storage.OpenGormDB under the hood) fails deterministically
// without needing any real database or key material.
func badStorageCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type:       "badtype",
			Encryption: config.EncryptionConfig{Enabled: true},
		},
	}
}

// ── authStatusWithConfig: openDatabase error ─────────────────────────────────

func TestAuthStatusWithConfig_DBOpenError(t *testing.T) {
	err := authStatusWithConfig(badStorageCfg())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

// ── runEnableAuthEncryption: config.Load error ───────────────────────────────

func TestRunEnableAuthEncryption_ConfigLoadError(t *testing.T) {
	t.Chdir(t.TempDir()) // no keyorix.yaml → config.Load("") fails
	t.Setenv("KEYORIX_CONFIG_PATH", "")

	err := enableCmd.RunE(enableCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load config")
}

// ── enableAuthEncryptionWithConfig: openDatabase error ───────────────────────

func TestEnableAuthEncryptionWithConfig_DBOpenError(t *testing.T) {
	err := enableAuthEncryptionWithConfig(badStorageCfg(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

// TestEnableAuthEncryptionWithConfig_WrongPassphrase covers the
// "authEnc.Initialize(passphrase); err != nil" branch: status is checked on a
// freshly constructed AuthEncryption handle (always initialized=false at that
// point, so the "already enabled" early return never fires here), then
// Initialize fails against already-provisioned key material with the wrong
// passphrase.
func TestEnableAuthEncryptionWithConfig_WrongPassphrase(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	t.Setenv("KEYORIX_MASTER_PASSWORD", "definitely-the-wrong-passphrase")

	err := enableAuthEncryptionWithConfig(cfg, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth encryption")
}

// ── runRotateAuthEncryption: openDatabase error, reached via the real ────────
// ── cobra shim (config.Load must succeed first). ─────────────────────────────

func TestRunRotateAuthEncryption_DBOpenError(t *testing.T) {
	cfgPath := writeConfig(t, badStorageConfigYAML) // storage.type: badtype
	t.Setenv("KEYORIX_CONFIG_PATH", cfgPath)

	require.NoError(t, authRotateCmd.Flags().Set("confirm", "true"))
	t.Cleanup(func() { _ = authRotateCmd.Flags().Set("confirm", "false") })

	err := authRotateCmd.RunE(authRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database")
}

// ── runRotateAuthEncryption: authEnc.Initialize error (wrong passphrase), ────
// ── reached via the real cobra shim with a real db + real key material. ──────

func TestRunRotateAuthEncryption_WrongPassphrase(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	cfg := newAuthLockTestConfig(t, workDir) // provisions the correct passphrase via KEYORIX_MASTER_PASSWORD
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	cfgYAML := writeConfig(t, `
storage:
  type: local
  database:
    path: `+cfg.Storage.Database.Path+`
  encryption:
    enabled: true
    dek_path: `+cfg.Storage.Encryption.DEKPath+`
    salt_path: `+cfg.Storage.Encryption.SaltPath+`
`)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgYAML)

	// Break the passphrase AFTER provisioning — runRotateAuthEncryption reads
	// it fresh via masterPassphrase(cfg) inside the shim.
	t.Setenv("KEYORIX_MASTER_PASSWORD", "definitely-the-wrong-passphrase")

	require.NoError(t, authRotateCmd.Flags().Set("confirm", "true"))
	t.Cleanup(func() { _ = authRotateCmd.Flags().Set("confirm", "false") })

	err := authRotateCmd.RunE(authRotateCmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth encryption")
}

// ── runRotateAuthEncryption: success path (real db + real key material, ─────
// ── correct passphrase) — covers the two success-print statements after ─────
// ── authEnc.RotateAuthEncryption succeeds, which no existing test reaches: ───
// ── TestRunRotateAuthEncryption_S27_ConfirmMissingWithRealConfig stops at the ─
// ── --confirm gate, TestRunRotateAuthEncryption_ConfirmTrue_LocalDB (s3) uses ─
// ── an empty passphrase against a config with no key material provisioned ────
// ── (outcome unasserted), and TestRunRotateAuthEncryption_WrongPassphrase ────
// ── (above) deliberately breaks the passphrase. ───────────────────────────────

func TestRunRotateAuthEncryption_Success(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	cfg := newAuthLockTestConfig(t, workDir) // sets KEYORIX_MASTER_PASSWORD to the correct passphrase

	// RotateDEKWithSweep re-encrypts every encrypted table it knows about, not
	// just the auth ones — provisionAuthLockTestDB only migrates the auth four,
	// which leaves "no such table: secret_nodes" etc. Migrate the full set (all
	// empty — the sweep just needs to see and pass over zero rows in each).
	db, dbErr := storage.OpenGormDB(cfg)
	if dbErr != nil {
		t.Fatalf("failed to open test db: %v", dbErr)
	}
	if err := db.AutoMigrate(
		&models.SecretNode{}, &models.SecretVersion{}, &models.Session{},
		&models.APIToken{}, &models.APIClient{}, &models.PasswordReset{},
		&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{},
	); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	provisionAuthLockTestKeys(t, cfg, workDir)

	cfgYAML := writeConfig(t, `
storage:
  type: local
  database:
    path: `+cfg.Storage.Database.Path+`
  encryption:
    enabled: true
    dek_path: `+cfg.Storage.Encryption.DEKPath+`
    salt_path: `+cfg.Storage.Encryption.SaltPath+`
`)
	t.Setenv("KEYORIX_CONFIG_PATH", cfgYAML)

	require.NoError(t, authRotateCmd.Flags().Set("confirm", "true"))
	t.Cleanup(func() { _ = authRotateCmd.Flags().Set("confirm", "false") })

	err := authRotateCmd.RunE(authRotateCmd, nil)
	require.NoError(t, err, "rotation against freshly-provisioned key material with the correct passphrase should succeed")
}

// ── validatePasswordResetTokens: unmigrated-rows query error ─────────────────

// TestValidatePasswordResetTokens_UnmigratedQueryError covers the SECOND query
// in validatePasswordResetTokens (the "token != ” AND ... encrypted_token IS
// NULL" lookup for still-unmigrated rows) — distinct from the already-covered
// first-query and per-row-decrypt error branches elsewhere in the suite. The
// table is created by hand WITHOUT the legacy "token" column (AutoMigrate would
// add a unique index on it that blocks a later ALTER TABLE ... DROP COLUMN, so
// this sidesteps that rather than fighting it): the first query (which only
// touches encrypted_token, over zero rows) still succeeds, but the second
// query fails with "no such column: token".
func TestValidatePasswordResetTokens_UnmigratedQueryError(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.Exec(`CREATE TABLE password_resets (
		id INTEGER PRIMARY KEY,
		user_id INTEGER,
		encrypted_token BLOB,
		token_metadata TEXT,
		expires_at DATETIME,
		created_at DATETIME
	)`).Error)

	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
	authEnc := encryption.NewAuthEncryption(cfg, tempDir, db)
	require.NoError(t, authEnc.Initialize("unmigrated-query-error-test-passphrase"))
	t.Cleanup(func() {
		if sqlDB, derr := db.DB(); derr == nil {
			_ = sqlDB.Close()
		}
	})

	_, verr := validatePasswordResetTokens(db, authEnc, false)
	require.Error(t, verr)
	assert.Contains(t, verr.Error(), "no such column")
}

// ── migrateAuthDataWithConfig: authEnc.Initialize error (wrong passphrase) ───

func TestMigrateAuthDataWithConfig_WrongPassphrase(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	// Break the passphrase after provisioning.
	t.Setenv("KEYORIX_MASTER_PASSWORD", "definitely-the-wrong-passphrase")

	err := migrateAuthDataWithConfig(cfg, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth encryption")
}

// ── validateAuthEncryptionWithConfig: authEnc.Initialize error ───────────────
// ── (wrong passphrase) ────────────────────────────────────────────────────────

func TestValidateAuthEncryptionWithConfig_WrongPassphrase(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	cfg := newAuthLockTestConfig(t, workDir)
	provisionAuthLockTestDB(t, cfg)
	provisionAuthLockTestKeys(t, cfg, workDir)

	t.Setenv("KEYORIX_MASTER_PASSWORD", "definitely-the-wrong-passphrase")

	err := validateAuthEncryptionWithConfig(cfg, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth encryption")
}
