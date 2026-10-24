package keyfiles

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keyorixhq/keyorix/internal/config"
)

// A gap of exactly keySetMtimeTolerance is within tolerance: the check is
// "gap > tolerance", not ">=". Kills the CONDITIONALS_BOUNDARY mutant at
// consistency.go:321 (gremlins MUTANT-SEC-1).
func TestVerifyKeySetConsistency_ExactlyAtTolerance_Passes(t *testing.T) {
	dir := t.TempDir()
	base := time.Unix(1_700_000_000, 0)
	writeFileAt(t, filepath.Join(dir, "salt.key"), base)
	writeFileAt(t, filepath.Join(dir, "dek.key"), base)
	writeFileAt(t, filepath.Join(dir, "share1.key"), base)
	writeFileAt(t, filepath.Join(dir, "share2.key"), base.Add(keySetMtimeTolerance))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type: "shamir", ShamirShareFiles: []string{"share1.key", "share2.key"},
		},
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a gap of exactly the tolerance must pass: %v", err)
	}

	// One second over is flagged, so the test above cannot pass vacuously.
	writeFileAt(t, filepath.Join(dir, "share2.key"), base.Add(keySetMtimeTolerance+time.Second))
	if err := VerifyKeySetConsistency(enc, dir); err == nil {
		t.Fatal("a gap of tolerance+1s must fail closed")
	}
}

// A write-capable provider ahead of a Shamir fallback in the provider list must
// not stop keyEstablishingGroups from reaching the Shamir share set. Kills the
// CONDITIONALS_NEGATION mutant on the wrapped-KEK resolve error check
// (consistency.go:184), which otherwise returns no groups and silently skips
// the whole mtime check whenever a KMS/TPM provider is configured.
func TestVerifyKeySetConsistency_KMSPrimaryShamirFallback_SharesMismatchFlagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	writeFileAt(t, filepath.Join(dir, "wrapped.key"), now)
	writeFileAt(t, filepath.Join(dir, "share1.key"), now)
	writeFileAt(t, filepath.Join(dir, "share2.key"), now.Add(48*time.Hour))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type: "aws-kms", WrappedKeyPath: "wrapped.key",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "shamir", ShamirShareFiles: []string{"share1.key", "share2.key"}},
			},
		},
	}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("shares 48h apart in a Shamir fallback must fail closed even with a KMS primary")
	}
	if !strings.Contains(err.Error(), "shamir share set (provider 1)") {
		t.Errorf("error must name the fallback's share group, got: %v", err)
	}
}
