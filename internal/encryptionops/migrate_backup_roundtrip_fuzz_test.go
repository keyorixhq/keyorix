package encryptionops

// FuzzMigrateBackupRoundTrip — oracle for
// INV-ENCRYPTION-migrate-backup-kept-and-restored-by-rename
// (internal/encryption/INVARIANTS.d/, REVIEW-ENCRYPTIONOPS-1 R1/R2). The
// migrate-provider path must, for a wrapped DEK of ANY content:
//
//   - back the DEK up to a NEW file (O_EXCL) that captures the DEK's bytes
//     exactly, never overwriting or truncating an earlier backup, even when two
//     backups are named in the same instant (distinctness then rests only on
//     the random suffix + O_EXCL retry);
//   - restore a backup over the active DEK path by atomic rename, reproducing
//     the backed-up bytes EXACTLY (a torn or lossy restore is silent key loss —
//     the worst outcome for a secrets manager: every secret becomes
//     undecryptable).
//
// The invariant was flagged by the IV1 invariant-map as "stale" because its
// Guard: line lists a Darwin-only companion test file (migrate_backup_atomic_
// darwin_test.go) absent on this platform; its main guards
// (migrate_backup_atomic_test.go) exist and pass, but they assert against FIXED
// byte strings. No fuzzer exercised the backup/restore roundtrip over arbitrary
// DEK content or arbitrary create→mutate→create→restore sequences. This target
// adds that metamorphic coverage.
//
// Time is pinned (migrateBackupNow) so every backup in one exec shares a
// timestamp: this forces the "same instant" collision-avoidance path, where
// non-overwriting depends purely on the random suffix and O_EXCL, not on the
// clock advancing.
//
// What this oracle does NOT verify:
//   - It does not simulate a crash between the re-wrap and the rename
//     (migrateRestoreCrashHook); the torn-write / crash-atomicity cases stay in
//     the deterministic tests (TestRestoreBackup_CrashBeforeRenameLeavesTheActiveDEKIntact).
//   - It does not exercise the key-set manifest (ks is nil, as in the existing
//     tests): the manifest staging/commit of a rollback is out of scope here.
//   - It does not test the exclusive dek.lock held by migrate-provider cleanup
//     (INV covers it via migrate_cleanup_lock_test.go); only the file naming and
//     restore atomicity are checked.
//   - fsync durability across a real power loss cannot be observed from a test;
//     only the logical file state after each call is asserted.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func FuzzMigrateBackupRoundTrip(f *testing.F) {
	// Pin the backup clock for the whole run: all backups in a single exec get
	// the same timestamp, so distinct names come only from the random suffix.
	origNow := migrateBackupNow
	migrateBackupNow = func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	f.Cleanup(func() { migrateBackupNow = origNow })

	// Seeds: tiny, binary, empty, and identical-before/after content.
	f.Add([]byte("wrapped-dek-v1"), []byte("wrapped-dek-v2-rewrapped"))
	f.Add([]byte{}, []byte("x"))
	f.Add([]byte{0x00, 0x01, 0x02, 0xff}, []byte{0x00, 0x01, 0x02, 0xff})
	f.Add([]byte("same"), []byte("same"))

	f.Fuzz(func(t *testing.T, dekV1, dekV2 []byte) {
		dir := t.TempDir()
		const dekPath = "dek.key"
		dekFull := filepath.Join(dir, dekPath)

		if err := os.WriteFile(dekFull, dekV1, 0o600); err != nil {
			t.Fatalf("seed active DEK: %v", err)
		}

		// First backup: captures dekV1 exactly.
		b1, err := CreateMigrateBackup(dir, dekPath)
		if err != nil {
			t.Fatalf("CreateMigrateBackup #1 failed on %d-byte DEK: %v", len(dekV1), err)
		}
		if !strings.HasPrefix(b1, dekPath+".migrate-backup.") {
			t.Fatalf("backup name %q lost the migrate-backup prefix", b1)
		}
		if got := readBytes(t, filepath.Join(dir, b1)); !bytes.Equal(got, dekV1) {
			t.Fatalf("backup #1 content != source DEK: got %d bytes, want %d", len(got), len(dekV1))
		}

		// Simulate the re-wrap step: the active DEK is replaced in place.
		if err := os.WriteFile(dekFull, dekV2, 0o600); err != nil {
			t.Fatalf("re-wrap active DEK: %v", err)
		}

		// Second backup, SAME pinned instant: must get a DISTINCT name and must
		// not have touched the first backup (O_EXCL never overwrites).
		b2, err := CreateMigrateBackup(dir, dekPath)
		if err != nil {
			t.Fatalf("CreateMigrateBackup #2 failed: %v", err)
		}
		if b2 == b1 {
			t.Fatalf("INV violated: two backups in the same instant got the SAME name %q — the second overwrote the first", b1)
		}
		if got := readBytes(t, filepath.Join(dir, b2)); !bytes.Equal(got, dekV2) {
			t.Fatalf("backup #2 content != re-wrapped DEK: got %d bytes, want %d", len(got), len(dekV2))
		}
		if got := readBytes(t, filepath.Join(dir, b1)); !bytes.Equal(got, dekV1) {
			t.Fatalf("INV violated: creating backup #2 changed backup #1's bytes (got %d, want the original %d) — a backup was truncated/overwritten", len(got), len(dekV1))
		}

		// Restore the FIRST backup over the active DEK: the active DEK must
		// become dekV1 EXACTLY (roundtrip), with no staging file left behind.
		RestoreBackup(dir, b1, dekPath, nil)
		if got := readBytes(t, dekFull); !bytes.Equal(got, dekV1) {
			t.Fatalf("INV violated: restore did not reproduce the backed-up DEK — got %d bytes, want the original %d (silent key loss)", len(got), len(dekV1))
		}
		if _, err := os.Stat(filepath.Join(dir, b1+".restoring")); !os.IsNotExist(err) {
			t.Fatalf("a completed restore left its staging file %q.restoring behind (stat err=%v)", b1, err)
		}
		// The backup itself is untouched by a restore (it may still be needed).
		if got := readBytes(t, filepath.Join(dir, b1)); !bytes.Equal(got, dekV1) {
			t.Fatalf("restore mutated the backup file it read from")
		}
	})
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- t.TempDir()-rooted path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
