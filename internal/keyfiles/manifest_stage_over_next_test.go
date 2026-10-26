package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// REVIEW-3714-DEEP-1 finding 3: StageManifest must not silently replace an
// earlier operation's intent that is still staged. The two-fault sequence from
// the review: an operation replaces dek.key and loses its manifest commit, a
// second operation stages its change and crashes before it writes anything.
// Replacing the first intent left the manifest recording neither the file's
// old content (Files) nor its current one (Next), and boot refused a coherent
// set as "does not match the key-set manifest".
func TestStageManifest_OverCompletedUncommittedIntent_RecordsItFirst(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	provisionGeneration(t, dir, enc)
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	dek := filepath.Join(dir, "dek.key")
	oldDEK := readFile(t, dek)
	rewrapped := []byte("re-wrapped-dek")

	// First operation: staged and written, commit lost.
	if err := ks.StageManifest(OpRewrapDEK, map[string][]byte{dek: rewrapped}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dek, rewrapped, 0o600); err != nil {
		t.Fatal(err)
	}
	// Second operation stages, then crashes before writing.
	if err := ks.StageManifest(OpRewrapRollback, map[string][]byte{dek: oldDEK}); err != nil {
		t.Fatalf("staging over a completed, uncommitted intent: %v", err)
	}

	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a coherent set must boot after a lost commit and a crashed stage: %v", err)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Files["dek.key"]; got.SHA256 != HashBytes(rewrapped) || got.Operation != OpRewrapDEK {
		t.Errorf("the earlier operation must be recorded before the new stage, entry = %+v", got)
	}
	if m.Next == nil || m.Next.Operation != OpRewrapRollback || m.Next.Generation != m.Generation+1 {
		t.Errorf("the new intent must be staged on top of it, next = %+v (generation %d)", m.Next, m.Generation)
	}
}

// An intent that stopped before it changed anything is dropped by the next
// stage, as boot treats it (IntentAbandoned).
func TestStageManifest_OverAbandonedIntent_ReplacesIt(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	provisionGeneration(t, dir, enc)
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	dek := filepath.Join(dir, "dek.key")
	before, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.StageManifest(OpRotateDEK, map[string][]byte{dek: []byte("never-written")}); err != nil {
		t.Fatal(err)
	}
	if err := ks.StageManifest(OpRotateDEK, map[string][]byte{dek: []byte("second-try")}); err != nil {
		t.Fatalf("staging over an abandoned intent: %v", err)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if m.Files["dek.key"] != before.Files["dek.key"] || m.Generation != before.Generation {
		t.Errorf("an abandoned intent must not be recorded, files = %+v generation %d", m.Files, m.Generation)
	}
	if m.Next == nil || m.Next.Files["dek.key"] != HashBytes([]byte("second-try")) {
		t.Errorf("the new intent must replace it, next = %+v", m.Next)
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("boot: %v", err)
	}
}

// An intent that changed only part of its files is left for boot to finish
// or refuse; staging over it is refused and the manifest is left unchanged.
func TestStageManifest_OverPartlyAppliedIntent_Refused(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK() // rotate-kek stopped between the DEK and the salt rename
	path := filepath.Join(f.dir, ManifestFileName)
	before := readFile(t, path)

	err := f.ks.StageManifest(OpRotateDEK, map[string][]byte{f.dek: []byte("another-dek")})
	if err == nil || !strings.Contains(err.Error(), "unresolved interrupted "+OpRotateKEK) {
		t.Fatalf("staging over a half-applied intent must be refused, naming it; got %v", err)
	}
	if string(readFile(t, path)) != string(before) {
		t.Error("a refused stage must leave the manifest unchanged")
	}
	if st := f.inspect(); st.Intent != IntentFinishable {
		t.Errorf("boot must still be able to finish the original rotation, intent = %v", st.Intent)
	}
}
