package keyfiles

import (
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func passwordSetConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{SaltPath: "kek.salt", DEKPath: "dek.key"}
}

// provisionGeneration writes a fresh salt and DEK into dir and records them as
// one manifest generation, as first boot does.
func provisionGeneration(t *testing.T, dir string, enc *config.EncryptionConfig) {
	t.Helper()
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ks.Required() {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, buf, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ks.CommitManifestFromDisk(OpFirstBoot, ks.Required()...); err != nil {
		t.Fatal(err)
	}
}

func cpFile(t *testing.T, src, dst string) {
	t.Helper()
	if out, err := exec.Command("cp", src, dst).CombinedOutput(); err != nil {
		t.Fatalf("cp %s %s: %v: %s", src, dst, err, out)
	}
}

// #2900 criterion 1, the red proof: a key directory assembled with plain cp
// from two different generations (generation A's salt and manifest,
// generation B's DEK). cp stamps every destination with the current time, so
// every mtime is identical — the pre-manifest check (presence plus a
// same-group mtime heuristic that did not even compare the DEK) passed this
// set, and the server only failed later, at the first unwrap. The manifest
// check refuses it at boot, naming the file that does not belong.
func TestVerifyKeySetConsistency_SetAssembledWithCpFromTwoGenerations_Refused(t *testing.T) {
	enc := passwordSetConfig()
	genA, genB, assembled := t.TempDir(), t.TempDir(), t.TempDir()
	provisionGeneration(t, genA, enc)
	provisionGeneration(t, genB, enc)

	cpFile(t, filepath.Join(genA, "kek.salt"), filepath.Join(assembled, "kek.salt"))
	cpFile(t, filepath.Join(genA, ManifestFileName), filepath.Join(assembled, ManifestFileName))
	cpFile(t, filepath.Join(genB, "dek.key"), filepath.Join(assembled, "dek.key"))
	now := time.Now()
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		if err := os.Chtimes(filepath.Join(assembled, n), now, now); err != nil {
			t.Fatal(err)
		}
	}

	err := VerifyKeySetConsistency(enc, assembled)
	if err == nil {
		t.Fatal("a set assembled from two generations (identical mtimes) must be refused at boot")
	}
	if !strings.Contains(err.Error(), filepath.Join(assembled, "dek.key")) {
		t.Errorf("the refusal must name the file from the other generation, got: %v", err)
	}
	if strings.Contains(err.Error(), filepath.Join(assembled, "kek.salt")+" (") {
		t.Errorf("the refusal must not blame the file that matches the manifest, got: %v", err)
	}

	// Green direction: each generation on its own boots.
	for _, d := range []string{genA, genB} {
		if err := VerifyKeySetConsistency(enc, d); err != nil {
			t.Errorf("a set from one generation must pass: %v", err)
		}
	}
}

// The same set copied whole (every file plus its manifest) with cp boots: the
// check depends on content, not on how the files were copied.
func TestVerifyKeySetConsistency_WholeSetCopiedWithCp_Passes(t *testing.T) {
	enc := passwordSetConfig()
	src, dst := t.TempDir(), t.TempDir()
	provisionGeneration(t, src, enc)
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		cpFile(t, filepath.Join(src, n), filepath.Join(dst, n))
	}
	if err := VerifyKeySetConsistency(enc, dst); err != nil {
		t.Fatalf("a whole set copied with cp must boot: %v", err)
	}
}

// A provider's wrapped-KEK blob that is far older than the salt and DEK (a
// rotate-kek on a deployment with a KMS fallback rewrites only those two) is
// the false refusal #2462 had to fix by grouping; the manifest compares each
// file with its own recorded hash, so age plays no part.
func TestVerifyKeySetConsistency_RotateKEKWithOlderFallbackBlob_Passes(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	enc.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "aws-kms", WrappedKeyPath: "kek.aws"}}
	provisionGeneration(t, dir, enc)
	old := time.Now().Add(-180 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "kek.aws"), old, old); err != nil {
		t.Fatal(err)
	}
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	newSalt, newDEK := []byte("new-salt-0123456789abcdef0123456"), []byte("new-wrapped-dek")
	files := map[string][]byte{filepath.Join(dir, "kek.salt"): newSalt, filepath.Join(dir, "dek.key"): newDEK}
	if err := ks.StageManifest(OpRotateKEK, files); err != nil {
		t.Fatal(err)
	}
	for p, data := range files {
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := ks.CommitManifest(OpRotateKEK, files); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("rotate-kek leaving a six-month-older fallback blob must boot: %v", err)
	}
}

// Shamir shares from two different splits in one provider: the case the old
// mtime heuristic could catch only when the copy preserved mtimes. The
// manifest catches it either way.
func TestVerifyKeySetConsistency_ShamirShareFromAnotherSplit_Refused(t *testing.T) {
	enc := passwordSetConfig()
	enc.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir", ShamirShareFiles: []string{"share1.hex", "share2.hex"}}}
	dir, other := t.TempDir(), t.TempDir()
	provisionGeneration(t, dir, enc)
	provisionGeneration(t, other, enc)
	cpFile(t, filepath.Join(other, "share2.hex"), filepath.Join(dir, "share2.hex"))
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil || !strings.Contains(err.Error(), "share2.hex") {
		t.Fatalf("a share from another split must be refused, naming it; got %v", err)
	}
}

// The DEK rotates on its own schedule (rotate-dek) and must not drag the rest
// of the set with it.
func TestVerifyKeySetConsistency_DEKRotatedAlone_Passes(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	provisionGeneration(t, dir, enc)
	ks, err := NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{filepath.Join(dir, "dek.key"): []byte("rotated-dek")}
	if err := ks.StageManifest(OpRotateDEK, files); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "dek.key"), []byte("rotated-dek"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ks.CommitManifest(OpRotateDEK, files); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a DEK rotated on its own must boot: %v", err)
	}
}
