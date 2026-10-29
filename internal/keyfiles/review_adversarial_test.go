package keyfiles

// REVIEW-AUDITVERIFY-KEYFILES-1: adversarial shapes of the key set that the
// existing tests did not pin. The manifest is not an authenticator (see
// manifest.go); these are the accident and crash shapes it must classify.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func mustVerify(t *testing.T, enc *config.EncryptionConfig, dir string) {
	t.Helper()
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("want a consistent set, got: %v", err)
	}
}

// A manifest from an earlier generation put back over a set a later rotation
// wrote (a key directory restored from two backups, manifest from the older):
// every file the later generation replaced is refused, naming it.
func TestReviewKF_ManifestFromAnotherGeneration_Refused(t *testing.T) {
	t.Parallel()
	enc := passwordSetConfig()
	dir := t.TempDir()
	provisionGeneration(t, dir, enc)
	mpath := filepath.Join(dir, ManifestFileName)
	older, err := os.ReadFile(mpath)
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	dek := filepath.Join(dir, "dek.key")
	newDEK := []byte(strings.Repeat("n", 32))
	if err := w.StageManifest(OpRotateDEK, map[string][]byte{dek: newDEK}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dek, newDEK, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := w.CommitManifest(OpRotateDEK, map[string][]byte{dek: newDEK}); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, enc, dir)

	if err := os.WriteFile(mpath, older, 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyKeySetConsistency(enc, dir)
	if err == nil || !strings.Contains(err.Error(), dek) {
		t.Fatalf("an older generation's manifest over a newer DEK must be refused naming the DEK, got: %v", err)
	}
}

// A torn manifest staging file left by a crash inside writeManifest (before
// its rename, here under the fixed name older binaries used) is never read:
// boot uses the committed manifest, and the next writer stages under a name of
// its own and leaves no staging file behind.
func TestReviewKF_TornManifestPending_IsIgnored(t *testing.T) {
	t.Parallel()
	enc := passwordSetConfig()
	dir := t.TempDir()
	provisionGeneration(t, dir, enc)
	torn := filepath.Join(dir, ManifestFileName+".pending")
	if err := os.WriteFile(torn, []byte(`{"format":1,"generation":9,"fil`), 0o600); err != nil {
		t.Fatal(err)
	}
	mustVerify(t, enc, dir)
	if _, err := ReconcileKeySet(enc, dir, ManifestFS{}); err != nil {
		t.Fatal(err)
	}
	w, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	salt := filepath.Join(dir, "kek.salt")
	if err := w.StageManifest(OpRotateKEK, map[string][]byte{salt: []byte(strings.Repeat("s", 32))}); err != nil {
		t.Fatal(err)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil || m.Next == nil || m.Next.Operation != OpRotateKEK {
		t.Fatalf("the staged intent is the writer's own: %+v, %v", m, err)
	}
	left, err := filepath.Glob(filepath.Join(dir, ManifestFileName+".pending-*"))
	if err != nil || len(left) != 0 {
		t.Fatalf("a committed write leaves no staging file, found %v (%v)", left, err)
	}
}

// Key files reached through symlinks (a Kubernetes Secret volume) are hashed
// through the link: a link retargeted at another generation's file is
// refused, and a link to a FIFO is refused at once, never waited on.
func TestReviewKF_SymlinkedKeyFiles(t *testing.T) {
	t.Parallel()
	enc := passwordSetConfig()
	real, other, dir := t.TempDir(), t.TempDir(), t.TempDir()
	provisionGeneration(t, real, enc)
	provisionGeneration(t, other, enc)
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		if err := os.Symlink(filepath.Join(real, n), filepath.Join(dir, n)); err != nil {
			t.Fatal(err)
		}
	}
	mustVerify(t, enc, dir)

	dek := filepath.Join(dir, "dek.key")
	if err := os.Remove(dek); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(other, "dek.key"), dek); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeySetConsistency(enc, dir); err == nil || !strings.Contains(err.Error(), dek) {
		t.Fatalf("a DEK link retargeted at another generation must be refused, got: %v", err)
	}

	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Remove(dek); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(fifo, dek); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- VerifyKeySetConsistency(enc, dir) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("a DEK link to a FIFO must be refused as not a regular file, got: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("boot blocked opening a FIFO behind a key-file symlink")
	}
}

// Two writers racing on one manifest without the key lock the callers hold
// (a broken lock): the committed manifest is never torn, whichever
// interleaving wins. With one shared staging name it was: both truncated and
// rewrote the same file and one renamed the mix into place, which boot then
// moved aside and re-adopted, dropping the generation record.
func TestReviewKF_RacingWriters_ManifestNeverTorn(t *testing.T) {
	t.Parallel()
	enc := passwordSetConfig()
	dir := t.TempDir()
	provisionGeneration(t, dir, enc)
	salt, dek := filepath.Join(dir, "kek.salt"), filepath.Join(dir, "dek.key")
	for range 20 {
		var wg sync.WaitGroup
		for i, p := range []string{salt, dek} {
			wg.Go(func() {
				w, err := NewSetWriter(enc, dir)
				if err != nil {
					t.Error(err)
					return
				}
				_ = w.CommitManifest(OpRotateDEK, map[string][]byte{p: []byte(strings.Repeat(string(rune('a'+i)), 32))})
			})
		}
		wg.Wait()
		if _, err := LoadManifest(filepath.Join(dir, ManifestFileName)); err != nil {
			t.Fatalf("racing writers left a manifest that does not load: %v", err)
		}
	}
}

// The same race, made deterministic: writer B stages (and then fails to
// rename) between writer A's staging write and A's rename. A must still
// install its own manifest. With one shared staging name, B overwrote A's
// staged bytes and its failure cleanup deleted A's staging file, so A's
// commit failed (or, had B renamed, installed B's content as A's).
func TestReviewKF_InterleavedWriter_DoesNotTouchAnothersStagingFile(t *testing.T) {
	t.Parallel()
	enc := passwordSetConfig()
	dir := t.TempDir()
	provisionGeneration(t, dir, enc)
	salt, dek := filepath.Join(dir, "kek.salt"), filepath.Join(dir, "dek.key")
	def := ManifestFS{}.withDefaults()
	b, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	b = b.WithFS(ManifestFS{Rename: func(string, string) error { return errors.New("writer B stopped before its rename") }})
	a, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	a = a.WithFS(ManifestFS{WriteSync: func(d, name string, data []byte) error {
		if err := def.WriteSync(d, name, data); err != nil {
			return err
		}
		if err := b.CommitManifest(OpRotateDEK, map[string][]byte{dek: []byte(strings.Repeat("b", 32))}); err == nil {
			t.Error("test bug: writer B was meant to fail")
		}
		return nil
	}})
	newSalt := []byte(strings.Repeat("a", 32))
	if err := a.CommitManifest(OpRotateKEK, map[string][]byte{salt: newSalt}); err != nil {
		t.Fatalf("writer A's commit failed because of writer B: %v", err)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.Files["kek.salt"]; got.SHA256 != HashBytes(newSalt) || got.Operation != OpRotateKEK {
		t.Fatalf("the committed manifest is not writer A's: salt entry %+v", got)
	}
}
