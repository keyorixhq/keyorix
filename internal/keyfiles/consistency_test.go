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

// A provider's wrapped-KEK blob being much older than the salt is NOT
// flagged, and this is the correction the coordinator's review asked for
// rather than a relaxation.
//
// The previous shape of this check compared every KEK-establishing file
// against the oldest in the whole set, and asserted (in this test's former
// body) that "there is no legitimate operation that rewraps the KEK
// provider's own blob without also touching the salt". There is:
// commitNewKEKFiles -- `keyorix encryption rotate-kek`, a documented,
// intended operation -- rewrites ONLY the salt and the DEK. A deployment with
// a passphrase KEK plus a KMS/TPM/Shamir fallback therefore leaves that
// fallback's blob at its original age, and some weeks later the server
// refuses to boot having been asked to do nothing unusual. The old assertion
// locked that false refusal in.
//
// RED on the pre-fix whole-set comparison: this test fails with
// "key material set looks mixed from different generations: .../wrapped.key".
func TestVerifyKeySetConsistency_KEKRotationLeavesProviderBlobOlder_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	// rotate-kek just rewrote salt + DEK; the KMS fallback's blob is untouched.
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	writeFileAt(t, filepath.Join(dir, "wrapped.key"), now.Add(-90*24*time.Hour))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{Type: "aws-kms", WrappedKeyPath: "wrapped.key"},
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("an ordinary rotate-kek must not make the server refuse to boot: %v", err)
	}
}

// The one case the mtime heuristic can still legitimately speak about: a
// single Shamir provider's share files. The split writes every share in ONE
// operation, so shares of different ages within one provider really are an
// inconsistent set -- and this is the only group with more than one member,
// i.e. the only place the check is not comparing a file against itself.
func TestVerifyKeySetConsistency_ShamirSharesFromDifferentGenerations_Flagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	writeFileAt(t, filepath.Join(dir, "share1.key"), now)
	writeFileAt(t, filepath.Join(dir, "share2.key"), now.Add(48*time.Hour))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type: "shamir", ShamirShareFiles: []string{"share1.key", "share2.key"},
		},
	}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil {
		t.Fatal("two shares of one Shamir provider 48h apart must fail closed")
	}
	if !strings.Contains(err.Error(), "share2.key") {
		t.Errorf("error must name the mismatched file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "shamir share set") {
		t.Errorf("error must name the GROUP, so the operator knows which operation to re-run, got: %v", err)
	}
}

// Two DIFFERENT Shamir providers (a primary and a fallback) are separate
// operations, so shares that are old in one and new in the other are not a
// finding -- the companion that stops the grouping being implemented as
// "all shamir shares anywhere, together".
func TestVerifyKeySetConsistency_ShamirSharesAcrossProviders_NotFlagged(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	writeFileAt(t, filepath.Join(dir, "salt.key"), now)
	writeFileAt(t, filepath.Join(dir, "dek.key"), now)
	writeFileAt(t, filepath.Join(dir, "a1.key"), now)
	writeFileAt(t, filepath.Join(dir, "a2.key"), now)
	writeFileAt(t, filepath.Join(dir, "b1.key"), now.Add(-120*24*time.Hour))
	writeFileAt(t, filepath.Join(dir, "b2.key"), now.Add(-120*24*time.Hour))
	enc := &config.EncryptionConfig{
		SaltPath: "salt.key", DEKPath: "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type: "shamir", ShamirShareFiles: []string{"a1.key", "a2.key"},
			Fallbacks: []config.KeyProviderConfig{
				{Type: "shamir", ShamirShareFiles: []string{"b1.key", "b2.key"}},
			},
		},
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("two independently-provisioned Shamir providers must not be compared against each other: %v", err)
	}
}

// A leftover "*.pending" rotation-staging sibling must NOT be read as a
// partial set. RequiredKeyFilePaths never adds one (unlike Registry, which
// includes it when present for permission checks), so an interrupted rotation
// cannot turn into a refusal to boot on the presence/absence check.
//
// Deliberately NOT asserting that this state is detected: whether a leftover
// kek.salt.pending is harmless (commitNewKEKFiles crashed after writing it,
// active salt+DEK still coherent) or fatal (it crashed after the DEK rename,
// so the active DEK no longer unwraps under the active salt) is
// indistinguishable from presence and mtimes alone -- both states have the
// identical file layout. Telling them apart needs the per-file hashes of the
// manifest tracked in #2900, which is why this check's ledger claim is scoped
// to presence/absence only.
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
