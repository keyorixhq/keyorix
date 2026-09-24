//go:build !windows

package encryption

// rotate_kill_halfway_test.go — a deterministic (non-fuzz) "kill-halfway"
// regression test for the crash-safety guarantee documented on
// internal/encryptionops.RotateWithConfig and .RotateAuthEncryptionWithConfig
// (docs/cli-split-inventory.md §7 PR 12): a process kill at ANY point during
// `keyorix-server admin encryption rotate` leaves exactly one of the old or
// new DEK consistently active and every row decryptable under it.
//
// FuzzDEKSweepCrashConsistency (keymanager_sweep_crash_consistency_fuzz_test.go)
// already exhaustively fuzzes every durability checkpoint across randomized
// inputs — this test does not replace that. It exists as an explicit,
// human-readable regression tied to this PR's admin-command work, pinned to
// the single MOST DANGEROUS checkpoint: "sweep:after-sweep-commit", where the
// re-encryption transaction has already committed (rows are now under the
// NEW DEK) but the active dek.key file on disk is STILL the old one — the
// widest on-disk/in-DB inconsistency window a real kill -9 could land in.

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/storage/models"
)

func TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_RecoversCleanly(t *testing.T) {
	const passphrase = "kill-halfway-pass"
	const plaintext = "super-secret-value-at-risk-of-loss"

	db := newTestDB(t)
	svc, dir := newTestService(t, passphrase)
	dekBefore := append([]byte(nil), captureCurrentDEK(t, svc)...)

	nodeID := seedSecretNode(t, db, 1)
	versionID := seedSecretVersion(t, db, svc, nodeID, 1, 1, plaintext)

	// Arm the crash seam: panic the instant RotateDEKWithSweep reaches the
	// "committed but not promoted" checkpoint, simulating a kill -9 at
	// exactly that point.
	prev := rotationCheckpoint
	rotationCheckpoint = func(label string) {
		if label == "sweep:after-sweep-commit" {
			panic(rotationCrash{label})
		}
	}
	func() {
		defer func() {
			rotationCheckpoint = prev
			r := recover()
			if r == nil {
				t.Fatalf("expected the simulated crash to interrupt RotateDEKWithSweep, but it ran to completion")
			}
			if _, ok := r.(rotationCrash); !ok {
				panic(r) // a genuine bug in the code under test — do not swallow it
			}
		}()
		_, _ = svc.RotateDEKWithSweep(passphrase, db)
	}()

	// Model process death: a real crashed process's OS-held locks are freed
	// on exit. Best-effort, matching the existing fuzz harness's convention.
	svc.Shutdown()

	// RECOVERY: a fresh process over the same key dir + same DB, exactly as
	// server/main.go and `keyorix-server admin encryption rotate` start up —
	// RecoverInterruptedRotation(db) (which promotes the pending DEK because
	// the sweep's redo marker committed), then Initialize().
	rec := NewService(&config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}, dir)
	if err := rec.RecoverInterruptedRotation(db); err != nil {
		t.Fatalf("RecoverInterruptedRotation after simulated kill: %v", err)
	}
	if err := rec.Initialize(passphrase); err != nil {
		t.Fatalf("recovery Initialize after simulated kill: %v", err)
	}
	defer rec.Shutdown()

	// AVAILABILITY + VALUE INTEGRITY: the row committed just before the kill
	// must still decrypt to its original plaintext under the recovered
	// active DEK — this is the guarantee a "kill-halfway" test exists to
	// prove; a committed row that no longer decrypts under any recoverable
	// key is permanent, unacceptable data loss for a secrets store.
	var v models.SecretVersion
	if err := db.First(&v, versionID).Error; err != nil {
		t.Fatalf("fetch row %d after recovery: %v", versionID, err)
	}
	aad := SecretAAD(nodeID, 1, 1)
	got, err := rec.DecryptSecretWithAAD(v.EncryptedValue, aad)
	if err != nil {
		t.Fatalf("DATA LOSS: committed row=%d no longer decrypts under the recovered active DEK: %v", versionID, err)
	}
	if string(got) != plaintext {
		t.Fatalf("VALUE CORRUPTION: recovered %q, want %q", got, plaintext)
	}

	// The rotation must have actually COMPLETED via recovery (promoted the
	// new DEK), not silently reverted to the old one — otherwise this test
	// would pass for the wrong reason (never having rotated at all).
	dekAfter := captureCurrentDEK(t, rec)
	if string(dekAfter) == string(dekBefore) {
		t.Fatalf("expected recovery to promote the NEW DEK generated before the kill, but the active DEK is unchanged from before rotation")
	}

	// CONFIDENTIALITY: the retired old DEK must no longer decrypt the row.
	oldEncSvc, err := NewEncryptionService(dekBefore)
	if err != nil {
		t.Fatalf("build old EncryptionService: %v", err)
	}
	if enc, derr := DeserializeEncryptedData(v.EncryptedValue); derr == nil {
		if _, derr := oldEncSvc.DecryptWithAAD(enc, aad); derr == nil {
			t.Fatalf("RETIRED-DEK LIVE: the old (pre-rotation) DEK still decrypts the row after recovery completed the rotation")
		}
	}
}
