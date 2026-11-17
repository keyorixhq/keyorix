package encryption

// atrest_memory_canary_selftest_test.go — red/green proof for the NR1 at-rest &
// memory key-material oracles (atrest_memory_canary_fuzz_test.go). Each oracle
// is shown to FIRE on a planted leak and to PASS on a clean world. A guard
// nobody has watched fail is not a guard; these are the watched failures.
//
// The "plants" live only here, in test code, and are never reached by the
// fuzzer or by production code.

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func trackedRaw(w *keyWorld, label string) []byte {
	for _, tr := range w.tracked {
		if tr.label == label {
			return tr.raw
		}
	}
	return nil
}

// ─── Part A red/green: at-rest ───────────────────────────────────────────────

// TestAtRestOracle_DetectsPlantedDEKOnDisk: a raw DEK written to a file on disk
// (the shape of an accidental debug log of key material) must be caught.
func TestAtRestOracle_DetectsPlantedDEKOnDisk(t *testing.T) {
	w := newKeyWorld(t)
	w.step(0, 0) // encrypt one secret, so a DEK is tracked

	if fs := w.atRestFindings(); len(fs) != 0 {
		t.Fatalf("clean world should have no at-rest findings, got: %v", fs)
	}

	dek := trackedRaw(w, "DEK")
	if len(dek) == 0 {
		t.Fatal("test setup: no DEK tracked")
	}
	leak := filepath.Join(w.dir, "nr1-planted-debug.log")
	if err := os.WriteFile(leak, []byte("DEBUG dek="+hex.EncodeToString(dek)+"\n"), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	fs := w.atRestFindings()
	if !findingFor(fs, leak, "DEK") {
		t.Fatalf("RED PROOF FAILED: planted DEK-on-disk not detected; findings=%v", fs)
	}
}

// TestAtRestOracle_DetectsPlantedKEKOutsideAllowPath: a file-provider KEK is
// legitimately at rest in its own provider file (allow-path), but a COPY of it
// anywhere else must be caught.
func TestAtRestOracle_DetectsPlantedKEKOutsideAllowPath(t *testing.T) {
	w := newKeyWorld(t)
	w.step(2, 1) // migrate to a NEW file-provider KEK with known bytes

	// The KEK in its own provider file must NOT be flagged (allow-path works).
	if fs := w.atRestFindings(); len(fs) != 0 {
		t.Fatalf("clean world (KEK only in its own key file) should have no findings, got: %v", fs)
	}

	kek := trackedRaw(w, "KEK-file")
	if len(kek) == 0 {
		t.Fatal("test setup: no file KEK tracked")
	}
	stray := filepath.Join(w.dir, "nr1-planted-stray.txt")
	if err := os.WriteFile(stray, []byte(hex.EncodeToString(kek)), 0o600); err != nil {
		t.Fatalf("plant: %v", err)
	}

	fs := w.atRestFindings()
	if !findingFor(fs, stray, "KEK-file") {
		t.Fatalf("RED PROOF FAILED: planted KEK-outside-allow-path not detected; findings=%v", fs)
	}
}

// TestAtRestOracle_CleanLifecycleHasNoFindings: the green control — a full
// mixed lifecycle leaves no key material at rest out of place. If this ever
// goes red on main it is a real finding, not a flake.
func TestAtRestOracle_CleanLifecycleHasNoFindings(t *testing.T) {
	w := newKeyWorld(t)
	for i, op := range []byte{0, 1, 2, 0, 3, 1, 0} {
		w.step(op, i)
		if fs := w.atRestFindings(); len(fs) != 0 {
			t.Fatalf("GREEN CONTROL FAILED after op %d (%d): unexpected at-rest finding(s): %v", i, op, fs)
		}
	}
}

func findingFor(fs []finding, file, label string) bool {
	for _, fd := range fs {
		if sameFile(fd.file, file) && fd.label == label {
			return true
		}
	}
	return false
}

// ─── Part B red/green: memory ────────────────────────────────────────────────

// TestMemoryOracle_DEKWipeCheckIsNotVacuous: IsDEKWiped must report false while
// the DEK is live and true after Shutdown. A check that is always true would
// pass even if Shutdown stopped wiping; this proves it is load-bearing.
func TestMemoryOracle_DEKWipeCheckIsNotVacuous(t *testing.T) {
	w := newKeyWorld(t)
	es := w.svc.encryptionService
	if es == nil {
		t.Fatal("no encryption service")
	}
	if es.IsDEKWiped() {
		t.Fatal("GREEN CONTROL FAILED: DEK reported wiped while service is live")
	}
	w.svc.Shutdown()
	if !es.IsDEKWiped() {
		t.Fatal("RED: DEK not wiped after Shutdown (INV-ENCRYPTION-24)")
	}
}

// TestMemoryHeapScanner_DetectsLiveKey proves the heap-dump scanner is sensitive
// enough to find a key that is definitely present (the live DEK, before
// Shutdown). This validates the DETECTOR; it says nothing about whether a hit
// AFTER Shutdown is a defect (it is not, by itself — see the fuzzer header).
func TestMemoryHeapScanner_DetectsLiveKey(t *testing.T) {
	w := newKeyWorld(t)
	w.step(0, 0)
	hits := w.heapDumpHits()
	if hits < 0 {
		t.Skip("WriteHeapDump unavailable in this environment")
	}
	if hits == 0 {
		t.Fatalf("RED PROOF FAILED: heap scanner found no live key material in a heap dump while the DEK is live — the memory oracle cannot detect what it claims to")
	}
	t.Logf("heap scanner found %d live tracked key value(s) before Shutdown (detector sensitive)", hits)
}

// TestMemoryHardening_PostShutdownHeapResidue is the EXPLORATORY Part-B
// measurement for the report: after a mixed lifecycle + Shutdown + GC, how many
// tracked DEK/KEK values still have a 16-byte run present in a heap dump? This
// is HARDENING data, NOT an oracle — a positive is expected in Go (garbage not
// yet swept, GC-relocated copies, bytes that transited an immutable string) and
// is never a defect absent a documented zeroization claim for that exact copy.
// The ONE documented claim (INV-ENCRYPTION-24, EncryptionService.dek) is checked
// separately and exactly by IsDEKWiped.
func TestMemoryHardening_PostShutdownHeapResidue(t *testing.T) {
	w := newKeyWorld(t)
	for i, op := range []byte{0, 1, 2, 0, 1, 2, 0} {
		w.step(op, i)
	}
	nTracked := 0
	for _, tr := range w.tracked {
		if tr.label == "DEK" || tr.label == "KEK-file" {
			nTracked++
		}
	}
	dekWiped, heapHits := w.finishAndCheckMemory()
	if !dekWiped {
		t.Fatal("INV-ENCRYPTION-24: DEK not wiped after Shutdown")
	}
	if heapHits < 0 {
		t.Skip("WriteHeapDump unavailable")
	}
	t.Logf("POST-SHUTDOWN HEAP RESIDUE (HARDENING): %d of %d tracked DEK/KEK values still present in heap dump after Shutdown+GC", heapHits, nTracked)
}
