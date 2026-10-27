package encryptionops

// REVIEW-ENCRYPTIONOPS-1 R2: `migrate-provider cleanup` must not delete the
// backup of an in-flight migration. The admin tree's database-presence lock is
// all that kept them apart, and --force goes past it in flock mode; the
// key-directory lock (dek.lock), which migrate-provider holds exclusively for
// its whole run, is not bypassable.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/encryption"
)

func TestMigrateProviderCleanupWithConfig_RefusedWhileTheKeyLockIsHeld(t *testing.T) {
	for _, dryRun := range []bool{false, true} {
		dir := t.TempDir()
		cfg := testConfig(true)
		backupName := cfg.Storage.Encryption.DEKPath + ".migrate-backup.1700000000000000000-deadbeef"
		if err := os.WriteFile(filepath.Join(dir, backupName), []byte("backup-an-in-flight-migration-needs"), 0o600); err != nil {
			t.Fatalf("seed backup file: %v", err)
		}

		// What migrate-provider (openKeyWriter) or a live server holds.
		holder := encryption.NewService(&cfg.Storage.Encryption, dir)
		if err := holder.AcquireExclusiveKeyLock(); err != nil {
			t.Fatalf("holder.AcquireExclusiveKeyLock: %v", err)
		}

		out, err := captureOutput(t, func() error {
			return MigrateProviderCleanupWithConfig(cfg, dir, dryRun, true)
		})
		if err == nil {
			t.Fatalf("dry-run=%v: cleanup ran while another process held the key lock; output:\n%s", dryRun, out)
		}
		if !strings.Contains(err.Error(), "refusing to clean up migrate-backup files") || !strings.Contains(err.Error(), "Stop the server") {
			t.Fatalf("dry-run=%v: expected the key-lock refusal naming what to do, got: %v", dryRun, err)
		}
		if _, serr := os.Stat(filepath.Join(dir, backupName)); serr != nil {
			t.Fatalf("dry-run=%v: the backup of an in-flight migration was deleted: %v", dryRun, serr)
		}

		// Once the holder is gone, the same cleanup runs and releases the lock.
		holder.Shutdown()
		if _, err := captureOutput(t, func() error {
			return MigrateProviderCleanupWithConfig(cfg, dir, dryRun, true)
		}); err != nil {
			t.Fatalf("dry-run=%v: cleanup after the holder released the lock: %v", dryRun, err)
		}
		_, serr := os.Stat(filepath.Join(dir, backupName))
		if dryRun != (serr == nil) {
			t.Fatalf("dry-run=%v: backup present after cleanup = %v", dryRun, serr == nil)
		}
		next := encryption.NewService(&cfg.Storage.Encryption, dir)
		if err := next.AcquireExclusiveKeyLock(); err != nil {
			t.Fatalf("dry-run=%v: cleanup did not release the key lock: %v", dryRun, err)
		}
		next.Shutdown()
	}
}
