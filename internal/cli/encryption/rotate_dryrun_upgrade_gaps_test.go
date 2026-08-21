// rotate_dryrun_upgrade_gaps_test.go — coverage uplift for narrow error
// branches in rotateWithConfig, dryRunRotation, and upgradeAADWithConfig
// (encryption.go) that the existing suites (encryption_s2/s3/s22/s23/s24/s27,
// local_key_lock_test.go) don't reach:
//
//   - storage.OpenGormDB error (invalid storage.type), reached via
//     rotateWithConfig and dryRunRotation directly.
//   - the RotateDEKWithSweep / PreviewRotationSweep error branch, reached by
//     pointing a "local" storage config at a fresh, unmigrated sqlite file (no
//     schema for the sweep to query).
//   - initLocalKeyOpService's exclusive-lock refusal, reached via
//     dryRunRotation and upgradeAADWithConfig directly (mirrors
//     local_key_lock_test.go's pattern for validateWithConfig).
package encryption

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	enc "github.com/keyorixhq/keyorix/internal/encryption"
	"github.com/keyorixhq/keyorix/internal/storage"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const rotateGapsPassphrase = "rotate-dryrun-upgrade-gaps-passphrase-123"

// rotateGapsCfg returns an encryption-enabled config for the given storage
// type/db path, pointing key files at workDir-relative paths.
func rotateGapsCfg(storageType, dbPath string) *config.Config {
	cfg := &config.Config{}
	cfg.Storage.Type = storageType
	cfg.Storage.Database.Path = dbPath
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled:  true,
		DEKPath:  "dek.key",
		SaltPath: "kek.salt",
	}
	return cfg
}

// ── rotateWithConfig: storage.OpenGormDB error (invalid storage.type) ────────

func TestRotateWithConfig_DBOpenError(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("badtype", "")
	err := rotateWithConfig(cfg, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database for rotation")
}

// ── rotateWithConfig: RotateDEKWithSweep error (no DB schema to sweep) ───────

func TestRotateWithConfig_SweepError_NoSchema(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("local", filepath.Join(workDir, "empty.db"))
	err := rotateWithConfig(cfg, true, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DEK rotation failed")
}

// ── dryRunRotation: initLocalKeyOpService refusal while a live server ────────
// ── holds the exclusive lock ──────────────────────────────────────────────────

func TestDryRunRotation_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("local", filepath.Join(workDir, "dryrun.db"))

	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, setup.Initialize(rotateGapsPassphrase))
	setup.Shutdown()

	serverSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, serverSvc.Initialize(rotateGapsPassphrase))
	require.NoError(t, serverSvc.AcquireExclusiveKeyLock())
	defer serverSvc.Shutdown()

	err := dryRunRotation(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a live server or an in-progress rotation")
}

// ── dryRunRotation: storage.OpenGormDB error (invalid storage.type) ──────────

func TestDryRunRotation_DBOpenError(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("badtype", "")
	err := dryRunRotation(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to open database for dry-run rotation preview")
}

// ── dryRunRotation: PreviewRotationSweep error (no DB schema to preview) ─────

func TestDryRunRotation_PreviewError_NoSchema(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("local", filepath.Join(workDir, "empty.db"))
	err := dryRunRotation(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dry-run rotation preview failed")
}

// ── upgradeAADWithConfig: initLocalKeyOpService refusal while a live server ──
// ── holds the exclusive lock ──────────────────────────────────────────────────

func TestUpgradeAADWithConfig_RefusedWhileServerHoldsLock(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("local", filepath.Join(workDir, "upgrade.db"))

	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, setup.Initialize(rotateGapsPassphrase))
	setup.Shutdown()

	serverSvc := enc.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, serverSvc.Initialize(rotateGapsPassphrase))
	require.NoError(t, serverSvc.AcquireExclusiveKeyLock())
	defer serverSvc.Shutdown()

	err := upgradeAADWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "a live server or an in-progress rotation")
}

// ── upgradeAADWithConfig: success path (real db + schema, no live server) ────

// TestUpgradeAADWithConfig_Success drives upgradeAADWithConfig all the way
// through service.UpgradeAuthAAD succeeding, covering the "AAD upgrade
// complete" summary print that every other upgradeAADWithConfig test stops
// short of (they all exercise an earlier guard/error branch instead).
func TestUpgradeAADWithConfig_Success(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", rotateGapsPassphrase)

	cfg := rotateGapsCfg("local", filepath.Join(workDir, "upgrade-success.db"))

	setup := enc.NewService(&cfg.Storage.Encryption, workDir)
	require.NoError(t, setup.Initialize(rotateGapsPassphrase))
	setup.Shutdown()

	// UpgradeAuthAAD sweeps mfa_secrets/dynamic_secret_configs/dynamic_secret_leases —
	// migrate the (empty) schema so the sweep has tables to query successfully.
	db, dbErr := storage.OpenGormDB(cfg)
	require.NoError(t, dbErr)
	require.NoError(t, db.AutoMigrate(&models.MFASecret{}, &models.DynamicSecretConfig{}, &models.DynamicSecretLease{}))
	if sqlDB, derr := db.DB(); derr == nil {
		_ = sqlDB.Close()
	}

	err := upgradeAADWithConfig(cfg)
	require.NoError(t, err)
}

// ── fixPermsWithConfig: FixKeyFilePermissions error (missing salt file) ──────

// TestFixPermsWithConfig_FixKeyFilePermissionsFails covers fixPermsWithConfig's
// "failed to fix permissions" branch. FixKeyFilePermissions unconditionally
// tries to fix BOTH the DEK and salt file, regardless of key-provider type —
// using a "file" key provider (which never touches SaltPath at all) means
// Initialize succeeds without ever creating kek.salt, but FixKeyFilePermissions
// then fails to even open the (nonexistent) salt file, so the overall call
// returns an error.
func TestFixPermsWithConfig_FixKeyFilePermissionsFails(t *testing.T) {
	workDir := t.TempDir()
	t.Chdir(workDir)

	kekPath := filepath.Join(workDir, "external-kek.hex")
	kekHex := strings.Repeat("cd", 32) // 64 hex chars = 32 raw bytes (KEKSize)
	require.NoError(t, os.WriteFile(kekPath, []byte(kekHex), 0600))

	cfg := &config.Config{}
	cfg.Storage.Type = "local"
	cfg.Storage.Encryption = config.EncryptionConfig{
		Enabled: true,
		DEKPath: "dek.key",
		// SaltPath deliberately left pointing at a path that never gets created —
		// the "file" provider below never calls ensureSaltExists.
		SaltPath: "kek.salt",
		KeyProvider: config.KeyProviderConfig{
			Type:     "file",
			FilePath: kekPath,
		},
	}

	err := fixPermsWithConfig(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fix permissions")

	// Confirm kek.salt genuinely was never created — the failure is because
	// FixKeyFilePermissions can't open a file that doesn't exist, not some
	// other unrelated error.
	_, statErr := os.Stat(filepath.Join(workDir, "kek.salt"))
	assert.True(t, os.IsNotExist(statErr), "expected kek.salt to never be created by the file key provider")
}
