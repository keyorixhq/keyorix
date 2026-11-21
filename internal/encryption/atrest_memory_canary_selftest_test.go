package encryption

// atrest_memory_canary_selftest_test.go — red/green proof for the NR1 at-rest &
// memory key-material oracles (atrest_memory_canary_fuzz_test.go). Each oracle
// is shown to FIRE on a planted leak and to PASS on a clean world. A guard
// nobody has watched fail is not a guard; these are the watched failures.
//
// The "plants" live only here, in test code, and are never reached by the
// fuzzer or by production code.

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/storage/models"
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
// mixed lifecycle (ops 0 encrypt, 1 rotate DEK with sweep, 2 rewrap KEK, each
// at least twice, with secrets present before every rotation) leaves no key
// material at rest out of place. It also proves the lifecycle really ran: one
// new DEK generation per rotation, one new KEK per rewrap, and every secret row
// still decrypts to its value under the final DEK, i.e. each sweep re-encrypted
// it. A lifecycle whose ops all failed would otherwise pass this control
// unchanged. If this ever goes red on main it is a real finding, not a flake.
func TestAtRestOracle_CleanLifecycleHasNoFindings(t *testing.T) {
	ops := []byte{0, 1, 2, 0, 1, 2, 0}
	w := newKeyWorld(t)
	for i, op := range ops {
		w.step(op, i)
		if fs := w.atRestFindings(); len(fs) != 0 {
			t.Fatalf("GREEN CONTROL FAILED after op %d (%d): unexpected at-rest finding(s): %v", i, op, fs)
		}
	}

	opCount := map[byte]int{}
	for _, op := range ops {
		opCount[op%3]++
	}
	for _, c := range []struct {
		label string
		want  int
	}{
		{"DEK", 1 + opCount[1]},      // the initial DEK plus one per rotation
		{"KEK-file", 1 + opCount[2]}, // the initial KEK plus one per rewrap
		{"secret-value", opCount[0]},
	} {
		if got := trackedCount(w, c.label); got != c.want {
			t.Errorf("lifecycle did not run as driven: %d tracked %s value(s), want %d (ops %v)", got, c.label, c.want, ops)
		}
	}

	var versions []models.SecretVersion
	if err := w.db.Find(&versions).Error; err != nil {
		t.Fatalf("read secret versions: %v", err)
	}
	if len(versions) != opCount[0] {
		t.Fatalf("%d secret version row(s), want %d", len(versions), opCount[0])
	}
	for _, v := range versions {
		var node models.SecretNode
		if err := w.db.First(&node, v.SecretNodeID).Error; err != nil {
			t.Fatalf("secret version %d: parent node %d: %v", v.ID, v.SecretNodeID, err)
		}
		pt, err := w.svc.DecryptSecretWithAAD(v.EncryptedValue, SecretAAD(node.ID, node.ProjectID, v.VersionNumber))
		if err != nil {
			t.Errorf("secret version %d does not decrypt under the final DEK (sweep did not re-encrypt it): %v", v.ID, err)
			continue
		}
		if !trackedHas(w, "secret-value", pt) {
			t.Errorf("secret version %d decrypts to an untracked value", v.ID)
		}
	}
}

func trackedCount(w *keyWorld, label string) int {
	n := 0
	for _, tr := range w.tracked {
		if tr.label == label {
			n++
		}
	}
	return n
}

func trackedHas(w *keyWorld, label string, raw []byte) bool {
	for _, tr := range w.tracked {
		if tr.label == label && bytes.Equal(tr.raw, raw) {
			return true
		}
	}
	return false
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
