//go:build !windows

package encryption

import (
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// TestEnsureWrappedDEKExists_ShortWriteSelfHeals proves ensureWrappedDEKExists's
// write-pending→rename→syncdir pattern: a torn/short write during first-time DEK
// generation must never leave a corrupt-but-existing dek.key at the final path
// — os.Stat/IsNotExist must still see "no DEK yet" on the next attempt, so a
// retry self-heals instead of failing forever.
//
// Found via FuzzFaultInjectedOperations/opInit (STEP 3, 2026-09-24): before this
// fix, ensureWrappedDEKExists wrote straight to dek.key with no pending/rename
// indirection (unlike rewrap/KEK-rotation, which already had this pattern). A
// faultShortWrite left a file that EXISTED (bypassing the IsNotExist
// regeneration check) but was too short to unwrap — every subsequent Initialize
// failed with "wrapped key too short" forever, with no recovery short of an
// operator manually deleting the file by hand. Verified red without the fix
// (temporarily reverting ensureWrappedDEKExists to a single direct
// durableWriteSync(km.baseDir, km.dekPath, ...) call reproduces exactly that
// permanent failure here), green with it.
func TestEnsureWrappedDEKExists_ShortWriteSelfHeals(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.EncryptionConfig{Enabled: true, DEKPath: "dek.key", SaltPath: "kek.salt"}

	// Tear the FIRST attempt's write to the ONE seam this fix targets.
	restore := armFileFault("init:write-dek", &fileFault{kind: faultShortWrite, k: 5, err: errInjectedFault})
	svc := NewService(cfg, dir)
	if err := svc.Initialize("test-passphrase"); err == nil {
		t.Fatalf("harness: expected the injected short write to fail the first Initialize")
	}
	restore()

	// The retry — unfaulted, the real operator's actual next step — must
	// succeed. Before this fix, it failed forever with "wrapped key too short."
	svc2 := NewService(cfg, dir)
	if err := svc2.Initialize("test-passphrase"); err != nil {
		t.Fatalf("REGRESSION: a clean retry after a torn first-run DEK write still fails: %v", err)
	}

	probe := []byte("torn-write-regression-probe")
	ct, _, err := svc2.EncryptSecret(probe)
	if err != nil {
		t.Fatalf("post-retry service cannot encrypt: %v", err)
	}
	pt, err := svc2.DecryptSecret(ct)
	if err != nil || string(pt) != string(probe) {
		t.Fatalf("post-retry service round-trip failed: err=%v got=%q", err, pt)
	}
}
