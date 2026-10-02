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

// The DEK is EXCLUDED from the mtime-consistency check: RotateDEKWithSweep
// legitimately rewrites only the DEK, on its own schedule, without touching
// the salt. A DEK rotated long after the salt was established must NOT be
// flagged as mixed-generation.
func TestVerifyKeySetConsistency_DEKRotatedIndependently_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now.Add(-90*24*time.Hour)) // established 90 days ago
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)                        // rotated just now
	enc := &config.EncryptionConfig{SaltPath: "salt.key", DEKPath: "dek.key"}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("an independently-rotated DEK must not be flagged as mixed-generation: %v", err)
	}
}

// A KMS wrapped-key blob established 48h apart from the salt IS flagged --
// unlike the DEK, there is no legitimate operation that rewraps the KEK
// provider's own blob without also touching the salt (same-provider KEK
// rotation rewrites both together).
func TestVerifyKeySetConsistency_MixedGeneration_WrappedKeyFlagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	writeFileAt(t, filepath.Join(dir, "wrapped.key"), now.Add(48*time.Hour))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "wrapped.key"},
	}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("a wrapped-key blob 48h out of sync with the salt must fail closed")
	}
	if !strings.Contains(err.Error(), "wrapped.key") {
		t.Errorf("error must name the mismatched file, got: %v", err)
	}
}

// Exactly at the tolerance boundary (just under) must still pass -- no
// off-by-one flakiness.
func TestVerifyKeySetConsistency_JustUnderTolerance_Passes(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "wrapped.key"), now.Add(keySetMtimeTolerance-time.Minute))
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "wrapped.key"},
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a gap just under the tolerance must pass: %v", err)
	}
}
