package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// A write-capable provider ahead of a Shamir fallback in the provider list must
// not stop the check from reaching the fallback's share files. This was a
// mutation-kill test for the mtime heuristic (MUTANT-SEC-1: a negated
// wrapped-KEK resolve check returned no groups whenever a KMS/TPM provider was
// configured); the manifest check replaced that heuristic (#2900), so the same
// shape is now asserted against it: one share from another split is refused,
// named, with a KMS primary in front of it.
func TestVerifyKeySetConsistency_KMSPrimaryShamirFallback_ShareFromAnotherSplitFlagged(t *testing.T) {
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type: "aws-kms", WrappedKeyPath: "wrapped.key",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "shamir", ShamirShareFiles: []string{"share1.key", "share2.key"}},
			},
		},
	}
	dir, other := t.TempDir(), t.TempDir()
	provisionGeneration(t, dir, enc)
	provisionGeneration(t, other, enc)
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a freshly recorded set must pass, so the refusal below cannot pass vacuously: %v", err)
	}

	foreign, err := os.ReadFile(filepath.Join(other, "share2.key")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "share2.key"), foreign, 0o600); err != nil {
		t.Fatal(err)
	}
	err = VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("a Shamir fallback share from another split must fail closed even with a KMS primary")
	}
	if !strings.Contains(err.Error(), "share2.key") {
		t.Errorf("error must name the foreign share, got: %v", err)
	}
}
