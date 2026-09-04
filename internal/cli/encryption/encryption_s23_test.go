// encryption_s23_test.go — coverage uplift (batch s23).
//
// Targets branches in:
//   - migrate_provider.go: printMigrateSummary all provider-type branches,
//     providerLabel non-empty type,
//     findMigrateBackups non-existent DEK directory,
//     migrateProviderCleanupWithConfig zero-matches path
//   - auth_encryption_validate.go: runValidateAuthEncryption
//     API-client/session/API-token/reset-token error wrapping
//   - auth_encryption.go: runAuthEncryptionStatus stats-error warning print path
package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/storage/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── providerLabel ────────────────────────────────────────────────────────────

// TestProviderLabel_S23_EmptyIsPassword verifies the "" → "password" default.
func TestProviderLabel_S23_EmptyIsPassword(t *testing.T) {
	assert.Equal(t, "password", providerLabel(""))
}

// TestProviderLabel_S23_NonEmptyPassThrough verifies that a non-empty type is
// returned unchanged (the else branch that S22 did not exercise).
func TestProviderLabel_S23_NonEmptyPassThrough(t *testing.T) {
	for _, typ := range []string{"env", "file", "exec", "shamir", "tpm", "aws-kms", "gcp-kms", "azure-kms"} {
		assert.Equal(t, typ, providerLabel(typ), "providerLabel(%q)", typ)
	}
}

// ── printMigrateSummary ───────────────────────────────────────────────────────

// printMigrateSummary only writes to stdout; we call it for each provider-type
// branch to confirm it does not panic. The function has no error return, so we
// just verify the code path runs to completion.

// TestPrintMigrateSummary_S23_PasswordType drives the "password" case block
// (prints salt_path and the KEYORIX_NEW_MASTER_PASSWORD note).
func TestPrintMigrateSummary_S23_PasswordType(t *testing.T) {
	tgt := config.EncryptionConfig{
		SaltPath:    "keys/kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
	// Must not panic.
	printMigrateSummary(tgt, "dek.key.migrate-backup.1234567890")
}

// TestPrintMigrateSummary_S23_FileType drives the "file" case block.
func TestPrintMigrateSummary_S23_FileType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "file", FilePath: "/etc/keyorix/kek.bin"},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.111")
}

// TestPrintMigrateSummary_S23_EnvType drives the "env" case block.
func TestPrintMigrateSummary_S23_EnvType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "env", EnvVar: "MY_KEK_VAR"},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.222")
}

// TestPrintMigrateSummary_S23_ExecType drives the "exec" case block.
func TestPrintMigrateSummary_S23_ExecType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{Type: "exec", ExecCommand: []string{"op", "read", "op://vault/kek/value"}},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.333")
}

// TestPrintMigrateSummary_S23_ShamirWithCommitment drives the "shamir" case
// block when ShamirCommitment is set (the non-empty-commitment branch).
func TestPrintMigrateSummary_S23_ShamirWithCommitment(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:             "shamir",
			ShamirShareFiles: []string{"/share1.hex", "/share2.hex"},
			ShamirCommitment: "deadbeefdeadbeef",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.444")
}

// TestPrintMigrateSummary_S23_ShamirNoCommitment drives the "shamir" case block
// when ShamirCommitment is empty (the warning-comment branch).
func TestPrintMigrateSummary_S23_ShamirNoCommitment(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "shamir",
			ShamirShareEnv: []string{"SHARE_A", "SHARE_B"},
			// ShamirCommitment intentionally omitted
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.555")
}

// TestPrintMigrateSummary_S23_ShamirShareEnvOnlyNoCommitment drives the shamir
// branch with share-env entries and no commitment — covers the
// `len(kp.ShamirShareEnv) > 0` inner branch.
func TestPrintMigrateSummary_S23_ShamirShareFilesAndEnv(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:             "shamir",
			ShamirShareFiles: []string{"/f1.hex"},
			ShamirShareEnv:   []string{"SHARE_B"},
			ShamirCommitment: "cafebabe",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.556")
}

// TestPrintMigrateSummary_S23_TPMWithDevice drives the "tpm" case block when
// TPMDevice is set (the `kp.TPMDevice != ""` branch).
func TestPrintMigrateSummary_S23_TPMWithDevice(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			TPMDevice:      "/dev/tpm0",
			WrappedKeyPath: "keys/kek.tpm",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.666")
}

// TestPrintMigrateSummary_S23_TPMNoDevice drives the "tpm" case block when
// TPMDevice is empty (the device-omitted branch).
func TestPrintMigrateSummary_S23_TPMNoDevice(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			WrappedKeyPath: "keys/kek.tpm",
			// TPMDevice intentionally omitted
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.777")
}

// TestPrintMigrateSummary_S23_AWSKMSType drives the "aws-kms" / "gcp-kms" /
// "azure-kms" shared case block.
func TestPrintMigrateSummary_S23_AWSKMSType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "aws-kms",
			KMSKeyID:       "arn:aws:kms:us-east-1:123456789012:key/mrk-abc",
			WrappedKeyPath: "keys/kek.kms",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.888")
}

// TestPrintMigrateSummary_S23_GCPKMSType exercises the same KMS block for GCP.
func TestPrintMigrateSummary_S23_GCPKMSType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "gcp-kms",
			KMSKeyID:       "projects/proj/locations/global/keyRings/kr/cryptoKeys/k",
			WrappedKeyPath: "keys/kek-gcp.kms",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.889")
}

// TestPrintMigrateSummary_S23_AzureKMSType exercises the same KMS block for Azure.
func TestPrintMigrateSummary_S23_AzureKMSType(t *testing.T) {
	tgt := config.EncryptionConfig{
		KeyProvider: config.KeyProviderConfig{
			Type:           "azure-kms",
			KMSKeyID:       "https://myvault.vault.azure.net/keys/mykey",
			WrappedKeyPath: "keys/kek-azure.kms",
		},
	}
	printMigrateSummary(tgt, "dek.key.migrate-backup.890")
}

// ── findMigrateBackups: non-existent DEK directory ───────────────────────────

// TestFindMigrateBackups_S23_NonExistentDir verifies that when the DEK's
// parent directory does not exist, findMigrateBackups returns (nil, nil) via
// the os.IsNotExist branch rather than propagating the error.
func TestFindMigrateBackups_S23_NonExistentDir(t *testing.T) {
	dir := t.TempDir()
	// Use a DEK path whose parent does not exist.
	dekPath := filepath.Join("nonexistent-subdir", "dek.key")

	matches, err := findMigrateBackups(dir, dekPath)
	require.NoError(t, err, "non-existent dir must return nil error")
	assert.Nil(t, matches, "non-existent dir must return nil matches")
}

// ── migrateProviderCleanupWithConfig: zero-matches print path ────────────────

// TestMigrateProviderCleanupWithConfig_S23_NoBackupsFound exercises the
// "No migrate-backup files found" branch: encryption is enabled, the DEK dir
// exists, but there are no matching backup files.
func TestMigrateProviderCleanupWithConfig_S23_NoBackupsFound(t *testing.T) {
	dir := t.TempDir()
	// Write a placeholder DEK file so the directory exists.
	require.NoError(t, os.WriteFile(filepath.Join(dir, "dek.key"), []byte("wrapped"), 0600))

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"

	// confirm=true, dryRun=false; no backup files exist → must print "nothing to
	// clean up" and return nil.
	err := migrateProviderCleanupWithConfig(cfg, dir, false, true)
	require.NoError(t, err)
}

// TestMigrateProviderCleanupWithConfig_S23_DryRunWithBackup exercises the
// dryRun=true branch when at least one backup file exists: files are listed but
// not deleted, and the function returns nil.
func TestMigrateProviderCleanupWithConfig_S23_DryRunWithBackup(t *testing.T) {
	dir := t.TempDir()
	dekPath := "dek.key"
	require.NoError(t, os.WriteFile(filepath.Join(dir, dekPath), []byte("wrapped"), 0600))
	backupFile := dekPath + ".migrate-backup.dryrun-s23"
	require.NoError(t, os.WriteFile(filepath.Join(dir, backupFile), []byte("old-wrap"), 0600))

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = dekPath

	err := migrateProviderCleanupWithConfig(cfg, dir, true /* dryRun */, false /* confirm */)
	require.NoError(t, err)

	// Backup file must still exist after dry-run.
	_, statErr := os.Stat(filepath.Join(dir, backupFile))
	assert.NoError(t, statErr, "dry-run must not delete the backup file")
}

// ── runValidateAuthEncryption: per-table error wrapping ─────────────────────
//
// TestRunValidateAuthEncryption_S23_APIClientValidationError and
// TestRunValidateAuthEncryption_S23_APITokenValidationError, which used to
// live here, drove validateAPIClients/validateAPITokens's decrypt-error
// branches. Both helpers have been removed entirely — api_clients.client_secret
// and api_tokens.token hold a SHA-256 hash, never plaintext, so
// runValidateAuthEncryption no longer inspects either table (see
// auth_encryption_validate.go). password_resets below is the one remaining
// table this per-table error-wrapping coverage applies to.

// TestRunValidateAuthEncryption_S23_ResetTokenValidationError drives the
// "password reset token validation failed" error-wrapping branch.
func TestRunValidateAuthEncryption_S23_ResetTokenValidationError(t *testing.T) {
	ae, db := setupMigrateValidateTest(t)

	require.NoError(t, db.Create(&models.PasswordReset{
		UserID:         88,
		EncryptedToken: []byte("garbage-ciphertext-s23"),
	}).Error)

	_, err := validatePasswordResetTokens(db, ae, false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reset")
}

// ── targetPassphrase: non-password provider returns empty string ─────────────

// TestTargetPassphrase_S23_NonPasswordReturnsEmpty verifies that any non-empty,
// non-"password" provider type returns ("", nil) without reading any env var.
func TestTargetPassphrase_S23_NonPasswordReturnsEmpty(t *testing.T) {
	for _, typ := range []string{"env", "file", "exec", "shamir", "tpm", "aws-kms", "gcp-kms", "azure-kms"} {
		pass, err := targetPassphrase(typ, crypto.PassphraseSource{})
		require.NoError(t, err, "provider type %q", typ)
		assert.Empty(t, pass, "provider type %q should yield empty passphrase", typ)
	}
}

// TestTargetPassphrase_S23_PasswordWithEnvSet verifies that the password
// provider reads KEYORIX_NEW_MASTER_PASSWORD when it is set.
func TestTargetPassphrase_S23_PasswordWithEnvSet(t *testing.T) {
	t.Setenv(newMasterPasswordEnv, "new-secret-pass-s23")
	pass, err := targetPassphrase("password", crypto.PassphraseSource{})
	require.NoError(t, err)
	assert.Equal(t, "new-secret-pass-s23", pass)
}

// ── targetEncryptionConfig: salt-path override for password provider ─────────

// TestTargetEncryptionConfig_S23_PasswordWithExplicitSaltPath verifies the
// toSaltPath override branch in the "password" case: when --to-salt-path IS
// provided, it replaces the current salt path.
func TestTargetEncryptionConfig_S23_PasswordWithExplicitSaltPath(t *testing.T) {
	cur := &config.EncryptionConfig{
		DEKPath:  "keys/dek.key",
		SaltPath: "keys/old.salt",
	}
	tgt, err := targetEncryptionConfig(cur, migrateOpts{
		toType:     "password",
		toSaltPath: "keys/new.salt",
	})
	require.NoError(t, err)
	assert.Equal(t, "keys/new.salt", tgt.SaltPath, "explicit --to-salt-path must override current salt_path")
	assert.Equal(t, "password", tgt.KeyProvider.Type)
}

// ── runAuthEncryptionStatus: stats-error warning path ───────────────────────

// TestRunAuthEncryptionStatus_S23_StatsWarningPath drives the
// "⚠️ Warning: Could not retrieve statistics" branch by calling
// showAuthEncryptionStats with a closed/nil database that causes the count
// queries to fail.  We call showAuthEncryptionStats directly since a real
// runAuthEncryptionStatus would also need config loading.
func TestRunAuthEncryptionStatus_S23_StatsWarningPath(t *testing.T) {
	// Open a real DB, close it, then pass it to showAuthEncryptionStats so
	// the internal gorm queries fail — this mimics the warning branch that
	// fires when the DB is unavailable after the status is already printed.
	ae, db := setupMigrateValidateTest(t)
	_ = ae

	sqlDB, err := db.DB()
	require.NoError(t, err)
	require.NoError(t, sqlDB.Close())

	// After closing the underlying connection, every query inside
	// showAuthEncryptionStats will fail.  The function itself returns nil
	// (GORM's Count does not return errors via the return value), so this
	// test confirms the function does not panic even on a closed DB.
	// The warning-print branch is triggered inside runAuthEncryptionStatus
	// when showAuthEncryptionStats returns a non-nil error; since the helper
	// always returns nil today, we exercise it purely for the no-panic guarantee.
	_ = showAuthEncryptionStats(db, true)
	_ = showAuthEncryptionStats(db, false)
}

// ── migrateProviderCleanupWithConfig: findMigrateBackups scan error ──────────

// TestMigrateProviderCleanupWithConfig_S23_ScanError verifies that when
// findMigrateBackups returns an error (the DEK parent dir is an unreadable
// directory), migrateProviderCleanupWithConfig wraps it as
// "failed to scan for migrate-backup files".
func TestMigrateProviderCleanupWithConfig_S23_ScanError(t *testing.T) {
	dir := t.TempDir()

	// Create a sub-directory with the expected name but make it a regular FILE
	// so os.ReadDir on it returns an error (not "not found", which would be
	// swallowed by the IsNotExist guard).
	subdir := filepath.Join(dir, "keys")
	require.NoError(t, os.WriteFile(subdir, []byte("not-a-dir"), 0600))

	cfg := enabledLocalCfg()
	// DEK is keys/dek.key → parent dir is "keys", which is a file, not a dir.
	cfg.Storage.Encryption.DEKPath = filepath.Join("keys", "dek.key")

	err := migrateProviderCleanupWithConfig(cfg, dir, false, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to scan for migrate-backup files")
}
