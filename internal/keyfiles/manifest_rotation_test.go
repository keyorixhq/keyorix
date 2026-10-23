package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #2900 criterion 3: an interrupted operation is classified at boot from the
// recorded hashes, without a passphrase, and "harmless leftover staging" and
// "active set incoherent" lead to different outcomes. These build the exact
// on-disk states commitNewKEKFiles leaves at each step (the real rotation is
// crashed at each checkpoint in internal/encryption's
// TestRotateKEKCrashPoints_BootClassifiesAndRecovers).

type kekRotationFixture struct {
	t                *testing.T
	dir              string
	ks               *SetWriter
	salt, dek        string
	newSalt, newDEK  []byte
	stagedFilesByKey map[string][]byte
}

func newKEKRotationFixture(t *testing.T) *kekRotationFixture {
	t.Helper()
	dir := t.TempDir()
	enc := passwordSetConfig()
	provisionGeneration(t, dir, enc)
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	f := &kekRotationFixture{
		t: t, dir: dir, ks: ks,
		salt: filepath.Join(dir, "kek.salt"), dek: filepath.Join(dir, "dek.key"),
		newSalt: []byte("new-salt-0123456789abcdef0123456"), newDEK: []byte("new-wrapped-dek-under-new-kek"),
	}
	f.stagedFilesByKey = map[string][]byte{f.salt: f.newSalt, f.dek: f.newDEK}
	return f
}

func (f *kekRotationFixture) write(path string, data []byte) {
	f.t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// stageAndWritePending is commitNewKEKFiles up to kek:after-stage-manifest.
func (f *kekRotationFixture) stageAndWritePending() {
	f.t.Helper()
	f.write(f.salt+".pending", f.newSalt)
	f.write(f.dek+".pending", f.newDEK)
	if err := f.ks.StageManifest(OpRotateKEK, f.stagedFilesByKey); err != nil {
		f.t.Fatal(err)
	}
}

func (f *kekRotationFixture) renameDEK() {
	f.t.Helper()
	if err := os.Rename(f.dek+".pending", f.dek); err != nil {
		f.t.Fatal(err)
	}
}

func (f *kekRotationFixture) inspect() *KeySetState {
	f.t.Helper()
	st, err := InspectKeySet(passwordSetConfig(), f.dir)
	if err != nil {
		f.t.Fatalf("InspectKeySet: %v", err)
	}
	return st
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Crash after the pending files are written and the intent staged, before any
// active file changed: harmless. Boot passes, writes nothing, and says the
// salt staging file can be deleted (the DEK one is left to crash recovery).
func TestInterruptedRotateKEK_BeforeAnyRename_IsHarmlessLeftover(t *testing.T) {
	f := newKEKRotationFixture(t)
	oldSalt := readFile(t, f.salt)
	f.stageAndWritePending()

	if st := f.inspect(); st.Intent != IntentAbandoned {
		t.Fatalf("intent = %v, want abandoned", st.Intent)
	}
	res, err := ReconcileKeySet(passwordSetConfig(), f.dir, ManifestFS{})
	if err != nil {
		t.Fatalf("a rotation interrupted before it changed the active set must boot: %v", err)
	}
	if res.Finished != "" {
		t.Errorf("nothing may be finished from an abandoned rotation, got %q", res.Finished)
	}
	if string(readFile(t, f.salt)) != string(oldSalt) {
		t.Error("the active salt must be left alone")
	}
	joined := strings.Join(res.Warnings, "\n")
	if !strings.Contains(joined, f.salt+".pending") || !strings.Contains(joined, "can be deleted") {
		t.Errorf("expected a warning that the salt staging file is harmless, got %q", joined)
	}
	if !strings.Contains(joined, f.dek+".pending") || !strings.Contains(joined, "crash recovery") {
		t.Errorf("expected the DEK staging file to be left to crash recovery, got %q", joined)
	}
}

// Crash after the DEK rename, before the salt rename: the hazard window. The
// active DEK is wrapped under the new KEK while the active salt is still the
// old one; the pending salt holds exactly the staged content, so boot
// finishes the rename and records the generation.
func TestInterruptedRotateKEK_AfterDEKRename_IsFinishedAtBoot(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK()

	st := f.inspect()
	if st.Intent != IntentFinishable || len(st.Finish) != 1 || st.Finish[0].To != f.salt {
		t.Fatalf("intent = %v, finish = %+v; want finishable by renaming the pending salt", st.Intent, st.Finish)
	}
	res, err := ReconcileKeySet(passwordSetConfig(), f.dir, ManifestFS{})
	if err != nil {
		t.Fatalf("ReconcileKeySet: %v", err)
	}
	if res.Finished != OpRotateKEK {
		t.Errorf("Finished = %q, want %q", res.Finished, OpRotateKEK)
	}
	if string(readFile(t, f.salt)) != string(f.newSalt) {
		t.Error("the pending salt must now be the active salt")
	}
	if _, err := os.Stat(f.salt + ".pending"); !os.IsNotExist(err) {
		t.Errorf("the pending salt must be gone after the rename: %v", err)
	}
	m, err := LoadManifest(filepath.Join(f.dir, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if m.Next != nil || m.Files["kek.salt"].SHA256 != HashBytes(f.newSalt) || m.Files["dek.key"].SHA256 != HashBytes(f.newDEK) {
		t.Errorf("manifest after finishing = %+v, want both files committed at the new hashes", m)
	}
	if st := f.inspect(); st.Intent != IntentNone || len(st.Leftovers) != 0 {
		t.Errorf("a second boot must see a clean set, got intent %v leftovers %v", st.Intent, st.Leftovers)
	}
}

// The same file layout, but the pending salt is missing: the active set is
// incoherent and boot cannot finish it, so it refuses — the other outcome.
func TestInterruptedRotateKEK_AfterDEKRename_NoStagedSalt_Refused(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK()
	if err := os.Remove(f.salt + ".pending"); err != nil {
		t.Fatal(err)
	}
	err := VerifyKeySetConsistency(passwordSetConfig(), f.dir)
	if err == nil || !strings.Contains(err.Error(), "key material is incoherent") {
		t.Fatalf("new DEK under the old salt with no staged salt must be refused as incoherent, got %v", err)
	}
	if !strings.Contains(err.Error(), f.dek) || !strings.Contains(err.Error(), f.salt) {
		t.Errorf("the refusal must name the replaced and the stuck file, got %v", err)
	}
}

// A pending salt whose content is not the staged one (left from some other
// rotation) must not be renamed into place.
func TestInterruptedRotateKEK_AfterDEKRename_WrongStagedSalt_Refused(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK()
	f.write(f.salt+".pending", []byte("a-salt-from-another-rotation-xxx"))
	if _, err := ReconcileKeySet(passwordSetConfig(), f.dir, ManifestFS{}); err == nil || !strings.Contains(err.Error(), "incoherent") {
		t.Fatalf("a staging file that does not match the staged hash must not be promoted, got %v", err)
	}
	if string(readFile(t, f.salt+".pending")) != "a-salt-from-another-rotation-xxx" {
		t.Error("the refused staging file must be left untouched")
	}
}

// Crash after both renames, before the manifest commit: boot records it.
func TestInterruptedRotateKEK_AfterSaltRename_CommitIsRecorded(t *testing.T) {
	f := newKEKRotationFixture(t)
	f.stageAndWritePending()
	f.renameDEK()
	if err := os.Rename(f.salt+".pending", f.salt); err != nil {
		t.Fatal(err)
	}
	if st := f.inspect(); st.Intent != IntentCompleted {
		t.Fatalf("intent = %v, want completed", st.Intent)
	}
	res, err := ReconcileKeySet(passwordSetConfig(), f.dir, ManifestFS{})
	if err != nil || res.Finished != "" {
		t.Fatalf("ReconcileKeySet = %+v, %v; want the commit recorded without a finish", res, err)
	}
	m, err := LoadManifest(filepath.Join(f.dir, ManifestFileName))
	if err != nil || m.Next != nil || m.Files["kek.salt"].SHA256 != HashBytes(f.newSalt) {
		t.Fatalf("manifest = %+v, %v; want the rotation committed", m, err)
	}
}

// The remaining half of #2424: a restore that crashed between installing its
// files leaves some files at the restored hashes and the rest at the old ones.
// Restore stages no ".pending" files, so boot cannot finish it and refuses,
// naming both halves.
func TestInterruptedRestore_PartialInstall_Refused(t *testing.T) {
	f := newKEKRotationFixture(t)
	restored := map[string][]byte{f.salt: []byte("restored-salt-0123456789abcdef01"), f.dek: []byte("restored-dek")}
	if err := f.ks.StageManifest(OpRestore, restored); err != nil {
		t.Fatal(err)
	}
	f.write(f.salt, restored[f.salt]) // the crash: the DEK was never installed
	err := VerifyKeySetConsistency(passwordSetConfig(), f.dir)
	if err == nil || !strings.Contains(err.Error(), "interrupted restore") {
		t.Fatalf("a half-installed restore must be refused as an interrupted restore, got %v", err)
	}
}
