package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

func writeFileAt(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	writeFile(t, path)
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
}

func TestVerifyKeySetConsistency_NilConfig(t *testing.T) {
	if err := VerifyKeySetConsistency(nil, ""); err != nil {
		t.Fatalf("VerifyKeySetConsistency(nil) = %v, want nil", err)
	}
}

// Neither salt nor DEK exist yet -- a fresh install, about to generate them.
// Must pass cleanly, not error.
func TestVerifyKeySetConsistency_FreshInstall_BothAbsent(t *testing.T) {
	dir := t.TempDir()
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("fresh install (neither file exists) must pass: %v", err)
	}
}

// Both present, written at the same time -- the normal, healthy case.
func TestVerifyKeySetConsistency_BothPresent_SameGeneration(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now.Add(2*time.Second))
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a complete, same-generation set must pass: %v", err)
	}
}

// Salt exists, DEK doesn't -- a broken partial set. Must fail closed, naming
// both the present and the missing file.
func TestVerifyKeySetConsistency_PartialSet_SaltOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "salt.key"))
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("a partial set (salt present, DEK missing) must fail closed")
	}
	if !strings.Contains(err.Error(), "salt.key") || !strings.Contains(err.Error(), "dek.key") {
		t.Errorf("error must name both files, got: %v", err)
	}
}

// DEK exists, salt doesn't -- the other half of the same partial-set case.
func TestVerifyKeySetConsistency_PartialSet_DEKOnly(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "dek.key"))
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("a partial set (DEK present, salt missing) must fail closed")
	}
}

// A KMS wrapped-key blob present alongside salt+DEK, but the Shamir-share-
// style completeness check applies equally to it: missing it while the
// others exist is still a partial set.
func TestVerifyKeySetConsistency_PartialSet_MissingWrappedKey(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "salt.key"))
	writeFile(t, filepath.Join(dir, "dek.key"))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "wrapped.key"},
	}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("missing wrapped-key blob alongside a present salt+DEK must fail closed")
	}
	if !strings.Contains(err.Error(), "wrapped.key") {
		t.Errorf("error must name the missing wrapped-key file, got: %v", err)
	}
}

// The mtime-based cases that used to sit here (an independently rotated DEK,
// rotate-kek leaving an older provider blob, Shamir shares of different ages,
// the tolerance boundary) went with the mtime heuristic (#2900). Their
// manifest-based replacements are in manifest_consistency_test.go:
// TestVerifyKeySetConsistency_DEKRotatedAlone_Passes,
// TestVerifyKeySetConsistency_RotateKEKWithOlderFallbackBlob_Passes and
// TestVerifyKeySetConsistency_ShamirShareFromAnotherSplit_Refused.

// A leftover "*.pending" rotation-staging sibling must NOT be read as a
// partial set. RequiredKeyFilePaths never adds one (unlike Registry, which
// includes it when present for permission checks), so an interrupted rotation
// cannot turn into a refusal to boot on the presence/absence check.
//
// Whether such a leftover is harmless or the active set is incoherent is
// decided from the manifest's staged hashes, not from presence: see
// manifest_rotation_test.go (#2900).
func TestVerifyKeySetConsistency_LeftoverPendingFiles_AreNotAPartialSet(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	// The exact layout commitNewKEKFiles leaves on an interrupted rotation.
	writeFileAt(t, filepath.Join(dir, "salt.key.pending"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key.pending"), now)
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}

	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a leftover rotation-staging file must not be misread as a partial/inconsistent set: %v", err)
	}
	paths, err := RequiredKeyFilePaths(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range paths {
		if strings.HasSuffix(p, ".pending") {
			t.Errorf("RequiredKeyFilePaths must not treat a rotation-staging file as REQUIRED (it would make every completed rotation a partial set): %s", p)
		}
	}
}
