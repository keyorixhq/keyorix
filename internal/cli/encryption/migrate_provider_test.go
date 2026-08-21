package encryption

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/encryption"
)

// copyFile (and restoreBackup, which delegates to it) must refuse to write
// THROUGH a symlink at the destination: an attacker with write access to the
// backup's parent directory could otherwise pre-plant a symlink pointing at an
// arbitrary file this process can write, and the "backup"/"restore" write would
// silently clobber that file instead of the intended DEK/backup path.
func TestCopyFile_RefusesSymlinkDestination(t *testing.T) {
	dir := t.TempDir()

	src := filepath.Join(dir, "source.key")
	if err := os.WriteFile(src, []byte("wrapped-dek-bytes"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// A sentinel file OUTSIDE the intended destination that a symlink will point at.
	sentinel := filepath.Join(dir, "sentinel.txt")
	const sentinelContent = "do-not-touch"
	if err := os.WriteFile(sentinel, []byte(sentinelContent), 0600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	// Plant a symlink at the destination path pointing at the sentinel.
	dst := filepath.Join(dir, "dek.key.migrate-backup.evil")
	if err := os.Symlink(sentinel, dst); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := copyFile(src, dst)
	if err == nil {
		t.Fatalf("expected copyFile to refuse writing through a symlink destination, got nil error")
	}

	// The sentinel file must be untouched — not overwritten with the source's content.
	got, rerr := os.ReadFile(sentinel)
	if rerr != nil {
		t.Fatalf("read sentinel: %v", rerr)
	}
	if string(got) != sentinelContent {
		t.Fatalf("sentinel file was clobbered through the symlink: got %q, want %q", got, sentinelContent)
	}
}

// TestCopyFile_NewDestinationRestrictiveModeRegardlessOfUmask — regression test for
// G68: copyFile writes DEK/key material (the pre-migration wrapped-DEK backup, and
// the restoreBackup path), so a freshly-created destination must end up at mode 0600
// even under a permissive process umask (0022), not whatever OpenFile's perm
// argument would otherwise be masked down to.
func TestCopyFile_NewDestinationRestrictiveModeRegardlessOfUmask(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.key")
	if err := os.WriteFile(src, []byte("wrapped-dek-bytes"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(dir, "dst.key")

	oldUmask := syscall.Umask(0o022)
	defer syscall.Umask(oldUmask)

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected new destination mode 0600 regardless of umask, got %o", perm)
	}
}

// TestCopyFile_EnforcesModeOnPreexistingDestination — the finding (G68) specifically
// calls out that copyFile's os.OpenFile mode argument only applies when the
// destination is freshly created; O_TRUNC leaves an EXISTING file's mode untouched.
// A stale world-readable destination (e.g. a leftover DEK/backup path from an older
// build, or one created under a permissive umask before this fix) must be tightened
// to 0600 when copyFile writes new key material over it, not left as-is.
func TestCopyFile_EnforcesModeOnPreexistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.key")
	if err := os.WriteFile(src, []byte("new-wrapped-dek-bytes"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	dst := filepath.Join(dir, "dst.key")
	// Pre-create the destination with a world-readable mode.
	if err := os.WriteFile(dst, []byte("stale-content"), 0o644); err != nil {
		t.Fatalf("write pre-existing dst: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat dst: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected pre-existing destination mode to be tightened to 0600, got %o", perm)
	}

	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "new-wrapped-dek-bytes" {
		t.Fatalf("expected copy to overwrite content, got %q", got)
	}
}

func enabledLocalCfg() *config.Config {
	return &config.Config{
		Storage: config.StorageConfig{
			Type: "local",
			Encryption: config.EncryptionConfig{
				Enabled: true,
				DEKPath: "keys/dek.key",
			},
		},
	}
}

func TestMigrateProvider_RequiresConfirm(t *testing.T) {
	err := migrateProviderWithConfig(enabledLocalCfg(), migrateOpts{toType: "env", toEnvVar: "KEK"}, false)
	if err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected --confirm gate, got: %v", err)
	}
}

func TestMigrateProvider_RejectsRemoteStorage(t *testing.T) {
	cfg := enabledLocalCfg()
	cfg.Storage.Type = "remote"
	err := migrateProviderWithConfig(cfg, migrateOpts{toType: "env", toEnvVar: "KEK"}, true)
	if err == nil || !strings.Contains(err.Error(), "server host") {
		t.Fatalf("expected remote-storage rejection, got: %v", err)
	}
}

func TestMigrateProvider_RejectsDisabledEncryption(t *testing.T) {
	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.Enabled = false
	err := migrateProviderWithConfig(cfg, migrateOpts{toType: "env", toEnvVar: "KEK"}, true)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-encryption rejection, got: %v", err)
	}
}

func TestMigrateProvider_RequiresToType(t *testing.T) {
	err := migrateProviderWithConfig(enabledLocalCfg(), migrateOpts{}, true)
	if err == nil || !strings.Contains(err.Error(), "--to-type") {
		t.Fatalf("expected --to-type requirement, got: %v", err)
	}
}

// TestMigrateProvider_EndToEnd_PasswordToEnv drives the full CLI core: it
// bootstraps a password-derived install, migrates the KEK to the env provider, and
// confirms the env provider unwraps the same DEK and a backup was kept — all
// without a database (encrypt/decrypt are key-only operations).
func TestMigrateProvider_EndToEnd_PasswordToEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // migrateProviderWithConfig resolves key paths under cwd

	t.Setenv("KEYORIX_MASTER_PASSWORD", "Sup3r-Secret-Passphrase!")
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("gen kek: %v", err)
	}
	t.Setenv("KEYORIX_TARGET_KEK", hex.EncodeToString(raw))

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	opts := migrateOpts{toType: "env", toEnvVar: "KEYORIX_TARGET_KEK"}
	if err := migrateProviderWithConfig(cfg, opts, true); err != nil {
		t.Fatalf("migrate password → env: %v", err)
	}

	// A fresh service on the TARGET (env) provider must open the re-wrapped DEK and
	// round-trip a secret.
	tgt := cfg.Storage.Encryption
	tgt.KeyProvider = config.KeyProviderConfig{Type: "env", EnvVar: "KEYORIX_TARGET_KEK"}
	svc := encryption.NewService(&tgt, dir)
	if err := svc.Initialize(""); err != nil {
		t.Fatalf("open with env provider after migration: %v", err)
	}
	defer svc.Shutdown()
	ct, _, err := svc.EncryptSecret([]byte("hello"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	pt, err := svc.DecryptSecret(ct)
	if err != nil || string(pt) != "hello" {
		t.Fatalf("round-trip under env provider failed: pt=%q err=%v", pt, err)
	}

	// The previous wrapped DEK was backed up.
	matches, _ := filepath.Glob(filepath.Join(dir, "dek.key.migrate-backup.*"))
	if len(matches) == 0 {
		t.Fatalf("expected a dek.key.migrate-backup.* file")
	}
}

// TestMigrateProviderCleanup_EndToEnd runs a real migration (leaving a backup file
// behind), then confirms cleanup finds it, dry-run leaves it in place, and a
// confirmed run securely deletes it (#198).
func TestMigrateProviderCleanup_EndToEnd(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	t.Setenv("KEYORIX_MASTER_PASSWORD", "Sup3r-Secret-Passphrase!")
	raw := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		t.Fatalf("gen kek: %v", err)
	}
	t.Setenv("KEYORIX_TARGET_KEK", hex.EncodeToString(raw))

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	if err := migrateProviderWithConfig(cfg, migrateOpts{toType: "env", toEnvVar: "KEYORIX_TARGET_KEK"}, true); err != nil {
		t.Fatalf("migrate password -> env: %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "dek.key.migrate-backup.*"))
	if len(matches) != 1 {
		t.Fatalf("expected exactly one migrate-backup file, got %v", matches)
	}
	backupPath := matches[0]

	// Dry-run must list it but not delete it.
	if err := migrateProviderCleanupWithConfig(cfg, dir, true, false); err != nil {
		t.Fatalf("dry-run cleanup: %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("dry-run must not delete the backup file: %v", err)
	}

	// Without --confirm (and not --dry-run), it must refuse.
	if err := migrateProviderCleanupWithConfig(cfg, dir, false, false); err == nil || !strings.Contains(err.Error(), "--confirm") {
		t.Fatalf("expected --confirm gate, got: %v", err)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("unconfirmed cleanup must not delete the backup file: %v", err)
	}

	// Confirmed cleanup deletes it.
	if err := migrateProviderCleanupWithConfig(cfg, dir, false, true); err != nil {
		t.Fatalf("confirmed cleanup: %v", err)
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("expected backup file to be deleted, stat err = %v", err)
	}

	// A second run finds nothing left to clean up.
	if err := migrateProviderCleanupWithConfig(cfg, dir, false, true); err != nil {
		t.Fatalf("cleanup on empty state should be a no-op success: %v", err)
	}
}

func TestMigrateProviderCleanup_RejectsDisabledEncryption(t *testing.T) {
	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.Enabled = false
	err := migrateProviderCleanupWithConfig(cfg, t.TempDir(), false, true)
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-encryption rejection, got: %v", err)
	}
}

// TestMigrateProviderCleanup_SecureDeleteError_SymlinkBackup covers the
// securefiles.SecureDeleteFile error branch inside migrateProviderCleanupWithConfig:
// a migrate-backup path that's actually a symlink fails at SecureDeleteFile's
// O_NOFOLLOW open (ELOOP) rather than being silently "deleted". The symlink's
// target must exist, or SecureDeleteFile's own initial os.Stat would treat the
// (broken-link) path as already-gone and return nil instead of an error.
func TestMigrateProviderCleanup_SecureDeleteError_SymlinkBackup(t *testing.T) {
	dir := t.TempDir()
	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"

	target := filepath.Join(dir, "real-target.txt")
	if err := os.WriteFile(target, []byte("hi"), 0600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	backupPath := filepath.Join(dir, "dek.key.migrate-backup.1")
	if err := os.Symlink(target, backupPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	err := migrateProviderCleanupWithConfig(cfg, dir, false, true)
	if err == nil || !strings.Contains(err.Error(), "failed to securely delete") {
		t.Fatalf("expected a secure-delete failure for the symlinked backup, got: %v", err)
	}
}

// TestMigrateProvider_TargetConfigError covers migrateProviderWithConfig's
// "tgtEnc, err := targetEncryptionConfig(...); if err != nil { return err }"
// branch: --to-type is set (passing the earlier required-flag gate) but the
// type-specific fields targetEncryptionConfig itself validates are missing.
func TestMigrateProvider_TargetConfigError(t *testing.T) {
	cfg := enabledLocalCfg()
	err := migrateProviderWithConfig(cfg, migrateOpts{toType: "file"}, true)
	if err == nil || !strings.Contains(err.Error(), "--to-file-path") {
		t.Fatalf("expected --to-file-path requirement to propagate, got: %v", err)
	}
}

// TestMigrateProvider_RewrapFailsMissingTargetFile drives migrateProviderWithConfig
// far enough to reach oldSvc.RewrapDEKWithProvider — covering the "re-wrap
// failed" error-wrap branch — by pointing --to-file-path at a KEK file that
// doesn't exist. Also confirms the pre-rewrap backup is cleaned up on failure,
// matching the comment on that branch ("RewrapDEK leaves the active DEK
// untouched on failure — drop the backup").
func TestMigrateProvider_RewrapFailsMissingTargetFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("KEYORIX_MASTER_PASSWORD", "Sup3r-Secret-Passphrase!")

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	missingKEKPath := filepath.Join(dir, "does-not-exist.kek")
	opts := migrateOpts{toType: "file", toFilePath: missingKEKPath}

	err := migrateProviderWithConfig(cfg, opts, true)
	if err == nil || !strings.Contains(err.Error(), "re-wrap failed") {
		t.Fatalf("expected a re-wrap failure, got: %v", err)
	}

	matches, _ := filepath.Glob(filepath.Join(dir, "dek.key.migrate-backup.*"))
	if len(matches) != 0 {
		t.Errorf("expected the pre-rewrap backup to be cleaned up on failure, found: %v", matches)
	}
}

// TestMigrateProvider_BackupCopyFails_ReadOnlyDir covers migrateProviderWithConfig's
// "failed to back up current wrapped DEK" branch: copyFile's OpenFile(dst, O_CREATE)
// fails because the key directory itself has been made read-only. The DEK/salt are
// pre-provisioned (so oldSvc.Initialize below only needs to READ them, which a
// read-only-but-executable directory still permits) before the directory is
// chmod'd, matching TestRotateKEKCommand_RotateFailsOnReadOnlyKeyDir's pattern in
// rotate_kek_test.go.
func TestMigrateProvider_BackupCopyFails_ReadOnlyDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a read-only directory doesn't block writes")
	}

	const passphrase = "Sup3r-Secret-Passphrase!"

	dir := t.TempDir()
	t.Chdir(dir)

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	setup := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := setup.Initialize(passphrase); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	setup.Shutdown()

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	t.Setenv("KEYORIX_MASTER_PASSWORD", passphrase)

	opts := migrateOpts{toType: "env", toEnvVar: "KEYORIX_TARGET_KEK"}
	err := migrateProviderWithConfig(cfg, opts, true)
	if err == nil || !strings.Contains(err.Error(), "failed to back up current wrapped DEK") {
		t.Fatalf("expected a backup-copy failure, got: %v", err)
	}

	// No migrate-backup file should have been left behind — the copy never
	// succeeded, so nothing exists to clean up.
	matches, _ := filepath.Glob(filepath.Join(dir, "dek.key.migrate-backup.*"))
	if len(matches) != 0 {
		t.Errorf("expected no migrate-backup file after a failed backup copy, found: %v", matches)
	}
}

// TestMigrateProvider_VerifyFailsOnProviderReInitError covers migrateProviderWithConfig's
// "verification failed (target provider could not open)" branch. The target is an
// "exec" provider backed by a helper script that succeeds on its first invocation
// (consumed by RewrapDEKWithProvider re-wrapping the DEK) but fails on its second
// (consumed by the fresh verifySvc.Initialize call afterward) — deterministic via a
// counter file, no network/credentials involved. Also confirms the previous wrapped
// DEK is restored (the backup round-trips back onto the active DEK path) rather than
// left in the new, re-wrapped state.
func TestMigrateProvider_VerifyFailsOnProviderReInitError(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	const passphrase = "Sup3r-Secret-Passphrase!"
	t.Setenv("KEYORIX_MASTER_PASSWORD", passphrase)

	cfg := enabledLocalCfg()
	cfg.Storage.Encryption.DEKPath = "dek.key"
	cfg.Storage.Encryption.SaltPath = "kek.salt"

	// Snapshot the active DEK before migration so we can confirm restoreBackup put
	// it back unchanged after the verify failure below.
	setup := encryption.NewService(&cfg.Storage.Encryption, dir)
	if err := setup.Initialize(passphrase); err != nil {
		t.Fatalf("provision key material: %v", err)
	}
	setup.Shutdown()
	origDEK, err := os.ReadFile(filepath.Join(dir, "dek.key"))
	if err != nil {
		t.Fatalf("read original dek.key: %v", err)
	}

	counterPath := filepath.Join(dir, "counter")
	scriptPath := filepath.Join(dir, "kek-helper.sh")
	key := strings.Repeat("ab", 32) // 64 hex chars = 32 raw bytes (KEKSize)
	script := fmt.Sprintf("#!/bin/sh\n"+
		"n=$(cat %q 2>/dev/null || echo 0)\n"+
		"n=$((n+1))\n"+
		"echo \"$n\" > %q\n"+
		"if [ \"$n\" -ge 2 ]; then\n"+
		"  echo \"helper unavailable on second call\" >&2\n"+
		"  exit 1\n"+
		"fi\n"+
		"printf '%%s' %q\n",
		counterPath, counterPath, key)
	if err := os.WriteFile(scriptPath, []byte(script), 0o700); err != nil {
		t.Fatalf("write helper script: %v", err)
	}

	opts := migrateOpts{toType: "exec", toExecCommand: []string{scriptPath}}
	err = migrateProviderWithConfig(cfg, opts, true)
	if err == nil || !strings.Contains(err.Error(), "verification failed (target provider could not open)") {
		t.Fatalf("expected a verify-open failure, got: %v", err)
	}

	// The helper must actually have run twice — once for the re-wrap, once for the
	// failed verify — confirming this test reaches the branch it claims to.
	counterBytes, cerr := os.ReadFile(counterPath)
	if cerr != nil || strings.TrimSpace(string(counterBytes)) != "2" {
		t.Fatalf("expected the helper to have been invoked exactly twice, counter file: %q (err=%v)", counterBytes, cerr)
	}

	gotDEK, rerr := os.ReadFile(filepath.Join(dir, "dek.key"))
	if rerr != nil {
		t.Fatalf("read restored dek.key: %v", rerr)
	}
	if string(gotDEK) != string(origDEK) {
		t.Fatalf("expected the previous wrapped DEK to be restored after a failed verify, but it changed")
	}
}

func TestTargetEncryptionConfig(t *testing.T) {
	cur := &config.EncryptionConfig{DEKPath: "keys/dek.key", SaltPath: "keys/kek.salt"}

	t.Run("kms requires key id", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "aws-kms", toWrappedKeyPath: "keys/kek.kms"})
		if err == nil || !strings.Contains(err.Error(), "--to-kms-key-id") {
			t.Fatalf("expected kms key-id requirement, got: %v", err)
		}
	})

	t.Run("kms requires wrapped key path", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "gcp-kms", toKMSKeyID: "k"})
		if err == nil || !strings.Contains(err.Error(), "--to-wrapped-key-path") {
			t.Fatalf("expected wrapped-key-path requirement, got: %v", err)
		}
	})

	t.Run("kms wrapped path must differ from dek", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "azure-kms", toKMSKeyID: "k", toWrappedKeyPath: "keys/dek.key"})
		if err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Fatalf("expected DEK-path collision rejection, got: %v", err)
		}
	})

	t.Run("kms ok preserves dek path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "azure-kms", toKMSKeyID: "https://v.vault.azure.net/keys/k", toWrappedKeyPath: "keys/kek.kms"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.DEKPath != cur.DEKPath {
			t.Fatalf("DEK path should be preserved, got %q", tgt.DEKPath)
		}
		if tgt.KeyProvider.Type != "azure-kms" || tgt.KeyProvider.WrappedKeyPath != "keys/kek.kms" {
			t.Fatalf("unexpected target provider: %+v", tgt.KeyProvider)
		}
	})

	t.Run("kms encryption context carries through to a new wrapped path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{
			toType: "aws-kms", toKMSKeyID: "k", toWrappedKeyPath: "keys/kek-v2.kms",
			toKMSEncryptionContext: map[string]string{"keyorix-install": "prod-1"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.KeyProvider.KMSEncryptionContext["keyorix-install"] != "prod-1" {
			t.Fatalf("expected encryption context to carry through, got %+v", tgt.KeyProvider.KMSEncryptionContext)
		}
	})

	t.Run("azure-kms rejects an encryption context (no AAD input)", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{
			toType: "azure-kms", toKMSKeyID: "https://v.vault.azure.net/keys/k", toWrappedKeyPath: "keys/kek.kms",
			toKMSEncryptionContext: map[string]string{"keyorix-install": "prod-1"},
		})
		if err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatalf("expected azure-kms + context rejection, got: %v", err)
		}
	})

	t.Run("kms encryption context requires a new wrapped path, not the current one", func(t *testing.T) {
		curKMS := &config.EncryptionConfig{
			DEKPath: "keys/dek.key",
			KeyProvider: config.KeyProviderConfig{
				Type: "aws-kms", KMSKeyID: "k", WrappedKeyPath: "keys/kek.kms",
			},
		}
		_, err := targetEncryptionConfig(curKMS, migrateOpts{
			toType: "aws-kms", toKMSKeyID: "k", toWrappedKeyPath: "keys/kek.kms", // same path, same type
			toKMSEncryptionContext: map[string]string{"keyorix-install": "prod-1"},
		})
		if err == nil || !strings.Contains(err.Error(), "NEW --to-wrapped-key-path") {
			t.Fatalf("expected same-path context rejection, got: %v", err)
		}
	})

	t.Run("file requires path", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "file"})
		if err == nil || !strings.Contains(err.Error(), "--to-file-path") {
			t.Fatalf("expected file-path requirement, got: %v", err)
		}
	})

	t.Run("env requires var", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "env"})
		if err == nil || !strings.Contains(err.Error(), "--to-env-var") {
			t.Fatalf("expected env-var requirement, got: %v", err)
		}
	})

	t.Run("exec requires command", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "exec"})
		if err == nil || !strings.Contains(err.Error(), "--to-exec-command") {
			t.Fatalf("expected exec-command requirement, got: %v", err)
		}
	})

	t.Run("exec carries the resolver argv", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "exec", toExecCommand: []string{"op", "read", "op://vault/kek/value"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.KeyProvider.Type != "exec" || len(tgt.KeyProvider.ExecCommand) != 3 {
			t.Fatalf("expected exec provider with 3-element argv, got %+v", tgt.KeyProvider)
		}
	})

	t.Run("shamir requires at least 2 shares", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "shamir", toShareFiles: []string{"only-one"}})
		if err == nil || !strings.Contains(err.Error(), "at least 2 shares") {
			t.Fatalf("expected shamir threshold requirement, got: %v", err)
		}
	})

	t.Run("shamir carries the share sources", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "shamir", toShareFiles: []string{"a", "b"}, toShareEnv: []string{"C"}})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.KeyProvider.Type != "shamir" || len(tgt.KeyProvider.ShamirShareFiles) != 2 || len(tgt.KeyProvider.ShamirShareEnv) != 1 {
			t.Fatalf("expected shamir provider with 2 files + 1 env, got %+v", tgt.KeyProvider)
		}
	})

	t.Run("tpm requires a wrapped-key-path distinct from the DEK", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "tpm"})
		if err == nil || !strings.Contains(err.Error(), "--to-wrapped-key-path") {
			t.Fatalf("expected wrapped-key-path requirement, got: %v", err)
		}
		_, err = targetEncryptionConfig(cur, migrateOpts{toType: "tpm", toWrappedKeyPath: cur.DEKPath})
		if err == nil || !strings.Contains(err.Error(), "must differ from the DEK path") {
			t.Fatalf("expected DEK-path guard, got: %v", err)
		}
	})

	t.Run("tpm carries device + blob path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "tpm", toWrappedKeyPath: "keys/kek.tpm", toTPMDevice: "/dev/tpm0"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.KeyProvider.Type != "tpm" || tgt.KeyProvider.WrappedKeyPath != "keys/kek.tpm" || tgt.KeyProvider.TPMDevice != "/dev/tpm0" {
			t.Fatalf("expected tpm provider with device + blob path, got %+v", tgt.KeyProvider)
		}
	})

	t.Run("password overrides salt path", func(t *testing.T) {
		tgt, err := targetEncryptionConfig(cur, migrateOpts{toType: "password", toSaltPath: "keys/new.salt"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if tgt.SaltPath != "keys/new.salt" {
			t.Fatalf("expected salt path override, got %q", tgt.SaltPath)
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := targetEncryptionConfig(cur, migrateOpts{toType: "bogus"})
		if err == nil || !strings.Contains(err.Error(), "unknown --to-type") {
			t.Fatalf("expected unknown-type error, got: %v", err)
		}
	})
}
