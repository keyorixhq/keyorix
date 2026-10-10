package encryptionops

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

// --- TargetEncryptionConfig ----------------------------------------------

func baseEncConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}
}

func TestTargetEncryptionConfig_UnknownTypeRefuses(t *testing.T) {
	_, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "bogus"})
	if err == nil {
		t.Fatal("expected refusal for an unknown --to-type")
	}
}

func TestTargetEncryptionConfig_FileType_RequiresFilePath(t *testing.T) {
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "file"}); err == nil {
		t.Fatal("expected refusal when --to-file-path is missing")
	}
	tgt, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "file", ToFilePath: "/some/path"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tgt.KeyProvider.FilePath != "/some/path" {
		t.Fatalf("FilePath not propagated: %+v", tgt.KeyProvider)
	}
}

func TestTargetEncryptionConfig_EnvType_RequiresEnvVar(t *testing.T) {
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "env"}); err == nil {
		t.Fatal("expected refusal when --to-env-var is missing")
	}
}

func TestTargetEncryptionConfig_ExecType_RequiresCommand(t *testing.T) {
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "exec"}); err == nil {
		t.Fatal("expected refusal when --to-exec-command is missing")
	}
}

func TestTargetEncryptionConfig_ShamirType_RequiresAtLeastTwoShares(t *testing.T) {
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "shamir", ToShareFiles: []string{"a"}}); err == nil {
		t.Fatal("expected refusal with only 1 share source")
	}
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "shamir", ToShareFiles: []string{"a", "b"}}); err != nil {
		t.Fatalf("expected success with 2 share sources: %v", err)
	}
}

func TestTargetEncryptionConfig_TPMType_RequiresWrappedKeyPathDifferentFromDEK(t *testing.T) {
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "tpm"}); err == nil {
		t.Fatal("expected refusal when --to-wrapped-key-path is missing")
	}
	if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "tpm", ToWrappedKeyPath: "dek.key"}); err == nil {
		t.Fatal("expected refusal when --to-wrapped-key-path collides with the DEK path")
	}
}

func TestTargetEncryptionConfig_KMSTypes_RequireKeyIDAndWrappedPath(t *testing.T) {
	for _, kmsType := range []string{"aws-kms", "gcp-kms", "azure-kms"} {
		if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: kmsType}); err == nil {
			t.Fatalf("%s: expected refusal without --to-kms-key-id", kmsType)
		}
		if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: kmsType, ToKMSKeyID: "k"}); err == nil {
			t.Fatalf("%s: expected refusal without --to-wrapped-key-path", kmsType)
		}
		if _, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: kmsType, ToKMSKeyID: "k", ToWrappedKeyPath: "dek.key"}); err == nil {
			t.Fatalf("%s: expected refusal when wrapped-key-path collides with the DEK path", kmsType)
		}
	}
}

func TestTargetEncryptionConfig_AzureKMSRejectsEncryptionContext(t *testing.T) {
	_, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{
		ToType: "azure-kms", ToKMSKeyID: "k", ToWrappedKeyPath: "wrapped.key",
		ToKMSEncryptionContext: map[string]string{"install": "x"},
	})
	if err == nil {
		t.Fatal("expected refusal: azure-kms has no AAD input for its RSA-OAEP wrap")
	}
}

func TestTargetEncryptionConfig_KMSEncryptionContextRequiresNewWrappedPath(t *testing.T) {
	cur := baseEncConfig()
	cur.KeyProvider = config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "wrapped.key"}
	_, err := TargetEncryptionConfig(cur, MigrateOpts{
		ToType: "aws-kms", ToKMSKeyID: "k", ToWrappedKeyPath: "wrapped.key", // same path as current
		ToKMSEncryptionContext: map[string]string{"install": "x"},
	})
	if err == nil {
		t.Fatal("expected refusal: a context binding needs a NEW wrapped-key-path to actually take effect")
	}
}

func TestTargetEncryptionConfig_PasswordType_SetsCustomSaltPath(t *testing.T) {
	tgt, err := TargetEncryptionConfig(baseEncConfig(), MigrateOpts{ToType: "password", ToSaltPath: "kek2.salt"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tgt.SaltPath != "kek2.salt" {
		t.Fatalf("expected SaltPath to be overridden, got %q", tgt.SaltPath)
	}
}

// --- TargetPassphrase -----------------------------------------------------

func TestTargetPassphrase_PasswordType_ReadsNewPassphraseEnv(t *testing.T) {
	setNewPassphraseEnv(t, testNewPassphrase)
	got, err := TargetPassphrase("password", zeroPassSrc())
	if err != nil {
		t.Fatalf("TargetPassphrase: %v", err)
	}
	if got != testNewPassphrase {
		t.Fatalf("got %q, want %q", got, testNewPassphrase)
	}
}

func TestTargetPassphrase_NonPasswordType_ReturnsEmptyNoError(t *testing.T) {
	got, err := TargetPassphrase("file", zeroPassSrc())
	if err != nil {
		t.Fatalf("TargetPassphrase: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty passphrase for a non-password target type, got %q", got)
	}
}

// --- CopyFile / RestoreBackup ---------------------------------------------

func TestCopyFile_PreservesBytesAndTightensLoosePermissions(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "src.bin"), []byte("secret-key-material"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// Pre-create the destination with a loose mode to prove CopyFile tightens it
	// (O_TRUNC keeps a pre-existing file's mode untouched otherwise, G68).
	if err := os.WriteFile(filepath.Join(dir, "dst.bin"), []byte("stale"), 0o644); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := CopyFile(dir, "src.bin", "dst.bin"); err != nil {
		t.Fatalf("CopyFile: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dir, "dst.bin"))
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "secret-key-material" {
		t.Fatalf("CopyFile did not copy bytes exactly: got %q", got)
	}
	if mode := fileMode(t, filepath.Join(dir, "dst.bin")); mode != 0o600 {
		t.Fatalf("expected dst.bin to be tightened to 0600, got %v", mode)
	}
}

func TestCopyFile_RefusesPathTraversalInDestination(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "src.bin"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	outside := filepath.Join(filepath.Dir(dir), "escaped.bin")
	defer func() { _ = os.Remove(outside) }()

	if err := CopyFile(dir, "src.bin", "../escaped.bin"); err == nil {
		t.Fatal("expected CopyFile to refuse a destination path that escapes baseDir")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("a file was created outside baseDir despite the traversal attempt")
	}
}

func TestRestoreBackup_RestoresExactBytes(t *testing.T) {
	dir := chdirTemp(t)
	original := []byte("original-wrapped-dek-bytes-0123456789")
	if err := os.WriteFile(filepath.Join(dir, "backup.bin"), original, 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "active.bin"), []byte("corrupted-or-newer-bytes"), 0o600); err != nil {
		t.Fatalf("write active: %v", err)
	}

	RestoreBackup(dir, "backup.bin", "active.bin")

	got, err := os.ReadFile(filepath.Join(dir, "active.bin"))
	if err != nil {
		t.Fatalf("read active: %v", err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("RestoreBackup did not restore exact bytes: got %q, want %q", got, original)
	}
}

// --- ProviderLabel ----------------------------------------------------------

func TestProviderLabel(t *testing.T) {
	if got := ProviderLabel(""); got != "password" {
		t.Fatalf("empty type: got %q, want %q", got, "password")
	}
	if got := ProviderLabel("aws-kms"); got != "aws-kms" {
		t.Fatalf("non-empty type: got %q, want %q", got, "aws-kms")
	}
}

// --- MigrateProviderWithConfig: validation gates --------------------------

func TestMigrateProviderWithConfig_DisabledRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: "k"}, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestMigrateProviderWithConfig_RemoteStorageRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Type = "remote"
	err := MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: "k"}, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal for remote storage")
	}
	if !strings.Contains(err.Error(), "remote") {
		t.Fatalf("expected a remote-storage error, got: %v", err)
	}
}

func TestMigrateProviderWithConfig_MissingToTypeRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	err := MigrateProviderWithConfig(cfg, MigrateOpts{}, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal when --to-type is empty")
	}
	if !strings.Contains(err.Error(), "--to-type") {
		t.Fatalf("expected a --to-type error, got: %v", err)
	}
}

func TestMigrateProviderWithConfig_WithoutConfirmRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(true)
	err := MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: "k"}, false, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal without --confirm")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected a --confirm guidance error, got: %v", err)
	}
}

// migrateFixture bootstraps a real keydir in the current (chdir'd) dir under
// the baseline passphrase and encrypts one probe secret, for migration
// round-trip assertions. Returns cfg plus the probe ciphertext/metadata.
func migrateFixture(t *testing.T) (cfg *config.Config, probeCT []byte) {
	t.Helper()
	cfg = testConfig(true)
	setPassphraseEnv(t, testBaselinePassphrase)
	if err := InitWithConfig(cfg, zeroPassSrc()); err != nil {
		t.Fatalf("bootstrap InitWithConfig: %v", err)
	}
	baseDir, _ := os.Getwd()
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("svc.Initialize: %v", err)
	}
	defer svc.Shutdown()
	var err error
	probeCT, _, err = svc.EncryptSecret([]byte("migrate-provider-probe-value"))
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}
	return cfg, probeCT
}

func TestMigrateProviderWithConfig_InvalidTargetConfig_NoBackupCreated(t *testing.T) {
	chdirTemp(t)
	cfg, _ := migrateFixture(t)

	oldDEK, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}

	// "file" with no --to-file-path is invalid (TargetEncryptionConfig's own
	// gate) and must fail BEFORE any backup or key-file work.
	err = MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file"}, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("expected refusal for an incomplete target config")
	}
	matches, ferr := FindMigrateBackups(".", cfg.Storage.Encryption.DEKPath)
	if ferr != nil {
		t.Fatalf("FindMigrateBackups: %v", ferr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no backup file to be created, found: %v", matches)
	}
	newDEK, _ := os.ReadFile("dek.key")
	if !bytes.Equal(oldDEK, newDEK) {
		t.Fatal("dek.key must be untouched when the target config is invalid")
	}
}

func TestMigrateProviderWithConfig_WrongOldPassphraseFailsClosed_NoBackupLeftBehind(t *testing.T) {
	chdirTemp(t)
	cfg, probeCT := migrateFixture(t)

	oldDEK, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}

	setPassphraseEnv(t, testWrongPassphrase)
	keyFile := filepath.Join(t.TempDir(), "raw.key")
	rawKey := make([]byte, crypto.KEKSize)
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(rawKey)), 0o600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	stdout, err := captureOutput(t, func() error {
		return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: keyFile}, true, zeroPassSrc(), zeroPassSrc())
	})
	if err == nil {
		t.Fatal("expected migrate-provider to fail with the wrong old passphrase")
	}
	if strings.Contains(stdout+err.Error(), testWrongPassphrase) {
		t.Fatal("passphrase leaked into stdout/error output")
	}

	matches, ferr := FindMigrateBackups(".", cfg.Storage.Encryption.DEKPath)
	if ferr != nil {
		t.Fatalf("FindMigrateBackups: %v", ferr)
	}
	if len(matches) != 0 {
		t.Fatalf("expected no backup file left behind after an early failure, found: %v", matches)
	}
	newDEK, _ := os.ReadFile("dek.key")
	if !bytes.Equal(oldDEK, newDEK) {
		t.Fatal("dek.key must be untouched after a failed migration")
	}

	// The original passphrase must still open everything and decrypt the probe.
	setPassphraseEnv(t, testBaselinePassphrase)
	baseDir, _ := os.Getwd()
	svc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	if err := svc.Initialize(testBaselinePassphrase); err != nil {
		t.Fatalf("original passphrase no longer works after failed migration: %v", err)
	}
	defer svc.Shutdown()
	got, err := svc.DecryptSecret(probeCT)
	if err != nil || string(got) != "migrate-provider-probe-value" {
		t.Fatalf("probe did not survive failed migration: got %q, err %v", got, err)
	}
}

func TestMigrateProviderWithConfig_Success_FileProvider_PreservesSecretAndLeavesBackup(t *testing.T) {
	chdirTemp(t)
	cfg, probeCT := migrateFixture(t)

	oldDEK, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}

	keyFile := filepath.Join(t.TempDir(), "raw.key")
	rawKey := make([]byte, crypto.KEKSize)
	for i := range rawKey {
		rawKey[i] = byte(i + 1)
	}
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(rawKey)), 0o600); err != nil {
		t.Fatalf("write raw key file: %v", err)
	}

	if _, err := captureOutput(t, func() error {
		return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: keyFile}, true, zeroPassSrc(), zeroPassSrc())
	}); err != nil {
		t.Fatalf("MigrateProviderWithConfig: %v", err)
	}

	newDEK, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key after migration: %v", err)
	}
	if bytes.Equal(oldDEK, newDEK) {
		t.Fatal("dek.key's wrapping must change after a real migration")
	}

	matches, ferr := FindMigrateBackups(".", cfg.Storage.Encryption.DEKPath)
	if ferr != nil {
		t.Fatalf("FindMigrateBackups: %v", ferr)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly one backup file, found: %v", matches)
	}
	backupBytes, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if !bytes.Equal(backupBytes, oldDEK) {
		t.Fatal("backup does not contain the pre-migration wrapped DEK bytes")
	}

	// The DEK's plaintext value is unchanged: the probe, encrypted under the
	// OLD provider, still decrypts under the NEW (file) provider.
	tgtEnc := cfg.Storage.Encryption
	tgtEnc.KeyProvider = config.KeyProviderConfig{Type: "file", FilePath: keyFile}
	baseDir, _ := os.Getwd()
	newSvc := encryption.NewService(&tgtEnc, baseDir)
	if err := newSvc.Initialize(""); err != nil {
		t.Fatalf("new file provider must open the migrated DEK: %v", err)
	}
	defer newSvc.Shutdown()
	got, err := newSvc.DecryptSecret(probeCT)
	if err != nil || string(got) != "migrate-provider-probe-value" {
		t.Fatalf("DEK value changed across migration: got %q, err %v", got, err)
	}

	// The old password-based provider must no longer unwrap the DEK.
	oldSvc := encryption.NewService(&cfg.Storage.Encryption, baseDir)
	err = oldSvc.Initialize(testBaselinePassphrase)
	oldSvc.Shutdown()
	if err == nil {
		t.Fatal("the old password provider must be rejected after migrating to a different provider")
	}
}

// --- MigrateProviderCleanupWithConfig --------------------------------------

func TestMigrateProviderCleanupWithConfig_DisabledRefuses(t *testing.T) {
	chdirTemp(t)
	cfg := testConfig(false)
	err := MigrateProviderCleanupWithConfig(cfg, ".", false, true)
	if err == nil {
		t.Fatal("expected refusal when encryption is disabled")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected a disabled-encryption error, got: %v", err)
	}
}

func TestMigrateProviderCleanupWithConfig_NoBackupsFound_NoError(t *testing.T) {
	dir := chdirTemp(t)
	cfg := testConfig(true)
	if err := MigrateProviderCleanupWithConfig(cfg, dir, false, true); err != nil {
		t.Fatalf("expected no error when there is nothing to clean up, got %v", err)
	}
}

func TestMigrateProviderCleanupWithConfig_WithoutConfirmOrDryRunRefuses(t *testing.T) {
	dir := chdirTemp(t)
	cfg := testConfig(true)
	backupName := cfg.Storage.Encryption.DEKPath + ".migrate-backup.1"
	if err := os.WriteFile(filepath.Join(dir, backupName), []byte("stale-backup"), 0o600); err != nil {
		t.Fatalf("seed backup file: %v", err)
	}

	err := MigrateProviderCleanupWithConfig(cfg, dir, false, false)
	if err == nil {
		t.Fatal("expected refusal without --confirm or --dry-run")
	}
	if !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected a --confirm guidance error, got: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, backupName)); serr != nil {
		t.Fatal("backup file must still exist after a refused cleanup")
	}
}

func TestMigrateProviderCleanupWithConfig_DryRun_ListsButDoesNotDelete(t *testing.T) {
	dir := chdirTemp(t)
	cfg := testConfig(true)
	backupName := cfg.Storage.Encryption.DEKPath + ".migrate-backup.1"
	if err := os.WriteFile(filepath.Join(dir, backupName), []byte("stale-backup"), 0o600); err != nil {
		t.Fatalf("seed backup file: %v", err)
	}

	stdout, err := captureOutput(t, func() error {
		return MigrateProviderCleanupWithConfig(cfg, dir, true, false)
	})
	if err != nil {
		t.Fatalf("dry-run cleanup: %v", err)
	}
	if !strings.Contains(stdout, backupName) {
		t.Fatalf("expected the dry run to list the backup file, got:\n%s", stdout)
	}
	if _, serr := os.Stat(filepath.Join(dir, backupName)); serr != nil {
		t.Fatal("dry run must not delete the backup file")
	}
}

func TestMigrateProviderCleanupWithConfig_Confirm_DeletesBackupsOnlyNotActiveDEK(t *testing.T) {
	dir := chdirTemp(t)
	cfg := testConfig(true)
	backupName := cfg.Storage.Encryption.DEKPath + ".migrate-backup.1"
	if err := os.WriteFile(filepath.Join(dir, backupName), []byte("stale-backup"), 0o600); err != nil {
		t.Fatalf("seed backup file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, cfg.Storage.Encryption.DEKPath), []byte("active-dek-bytes"), 0o600); err != nil {
		t.Fatalf("seed active dek.key: %v", err)
	}

	if _, err := captureOutput(t, func() error {
		return MigrateProviderCleanupWithConfig(cfg, dir, false, true)
	}); err != nil {
		t.Fatalf("confirmed cleanup: %v", err)
	}

	if _, serr := os.Stat(filepath.Join(dir, backupName)); serr == nil {
		t.Fatal("expected the backup file to be deleted")
	}
	activeBytes, rerr := os.ReadFile(filepath.Join(dir, cfg.Storage.Encryption.DEKPath))
	if rerr != nil {
		t.Fatalf("active dek.key must survive cleanup: %v", rerr)
	}
	if string(activeBytes) != "active-dek-bytes" {
		t.Fatal("cleanup must never touch the active (non-backup) DEK file")
	}
}

// --- FindMigrateBackups -----------------------------------------------------

func TestFindMigrateBackups_FindsOnlyMatchingFiles(t *testing.T) {
	dir := chdirTemp(t)
	must := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	must("dek.key", "active")
	must("dek.key.migrate-backup.100", "backup-1")
	must("dek.key.migrate-backup.200", "backup-2")
	must("dek.key.pending", "unrelated")
	must("kek.salt", "unrelated")

	matches, err := FindMigrateBackups(dir, "dek.key")
	if err != nil {
		t.Fatalf("FindMigrateBackups: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 backup matches, got %v", matches)
	}
}
