package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
)

// #2900 criterion 4 (NEEDS ANDREI 5's recommendation, warn-and-adopt): a
// complete key set with no manifest — every install that predates it, on its
// first start after the upgrade — or an unparseable one boots: the current
// files are recorded once, with a WARN (and, from Service.ReconcileKeySet, an
// audit event). Only a set that is also partial is refused.

func writeSetWithoutManifest(t *testing.T, dir string, enc *config.EncryptionConfig) {
	t.Helper()
	provisionGeneration(t, dir, enc)
	if err := os.Remove(filepath.Join(dir, ManifestFileName)); err != nil {
		t.Fatal(err)
	}
}

func TestReconcile_PreManifestCompleteSet_IsAdoptedOnce(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	writeSetWithoutManifest(t, dir, enc)

	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("a complete pre-manifest set must pass the boot refusal: %v", err)
	}
	res, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil {
		t.Fatalf("ReconcileKeySet: %v", err)
	}
	if len(res.Adopted) != 2 || !strings.Contains(res.AdoptReason, "predates") {
		t.Fatalf("result = %+v, want both files adopted because the install predates the manifest", res)
	}
	if !strings.Contains(strings.Join(res.Warnings, "\n"), "adopted the current key files") {
		t.Errorf("adoption must be announced as a warning, got %q", res.Warnings)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil || m.Generation != 1 || m.Files["dek.key"].Operation != OpAdopted {
		t.Fatalf("manifest after adoption = %+v, %v; want generation 1, adopted entries", m, err)
	}

	again, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil || len(again.Adopted) != 0 {
		t.Fatalf("the second start must not adopt again: %+v, %v", again, err)
	}
}

// The guarantee starts at adoption: after it, a file from another generation
// is refused like on any install that always had a manifest.
func TestReconcile_AfterAdoption_MixedSetIsRefused(t *testing.T) {
	dir, other := t.TempDir(), t.TempDir()
	enc := passwordSetConfig()
	writeSetWithoutManifest(t, dir, enc)
	if _, err := ReconcileKeySet(enc, dir, ManifestFS{}); err != nil {
		t.Fatal(err)
	}
	provisionGeneration(t, other, enc)
	cpFile(t, filepath.Join(other, "dek.key"), filepath.Join(dir, "dek.key"))
	if err := VerifyKeySetConsistency(enc, dir); err == nil {
		t.Fatal("a DEK from another generation copied in after adoption must be refused")
	}
}

func TestReconcile_UnparseableManifest_IsMovedAsideAndAdopted(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	writeSetWithoutManifest(t, dir, enc)
	if err := os.WriteFile(filepath.Join(dir, ManifestFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("an unparseable manifest on a complete set must not refuse boot: %v", err)
	}
	res, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil {
		t.Fatalf("ReconcileKeySet: %v", err)
	}
	if !strings.Contains(res.AdoptReason, "unparseable") || len(res.Adopted) != 2 {
		t.Fatalf("result = %+v, want the set adopted because the manifest was unparseable", res)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ManifestFileName+".unparseable-*"))
	if len(matches) != 1 || string(readFile(t, matches[0])) != "{not json" {
		t.Fatalf("the unparseable manifest must be moved aside intact, found %v", matches)
	}
	if _, err := LoadManifest(filepath.Join(dir, ManifestFileName)); err != nil {
		t.Fatalf("a valid manifest must replace it: %v", err)
	}
}

// Missing manifest AND a partial set: refused, as without a manifest.
func TestVerify_PreManifestPartialSet_IsRefused(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	writeSetWithoutManifest(t, dir, enc)
	if err := os.Remove(filepath.Join(dir, "dek.key")); err != nil {
		t.Fatal(err)
	}
	err := VerifyKeySetConsistency(enc, dir)
	if err == nil || !strings.Contains(err.Error(), "incomplete set") {
		t.Fatalf("a partial set without a manifest must be refused, got %v", err)
	}
	if _, rerr := ReconcileKeySet(enc, dir, ManifestFS{}); rerr == nil {
		t.Fatal("ReconcileKeySet must refuse it too, and adopt nothing")
	}
	if _, serr := os.Stat(filepath.Join(dir, ManifestFileName)); !os.IsNotExist(serr) {
		t.Fatalf("nothing may be adopted from a partial set: %v", serr)
	}
}

// A provider added to the config after the manifest was written brings a file
// the manifest has never seen: adopted (warned), not refused.
func TestReconcile_ProviderAddedAfterManifest_FileIsAdopted(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	provisionGeneration(t, dir, enc)
	if err := os.WriteFile(filepath.Join(dir, "kek.aws"), []byte("kms-wrapped-kek"), 0o600); err != nil {
		t.Fatal(err)
	}
	enc.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "aws-kms", WrappedKeyPath: "kek.aws"}}
	res, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil {
		t.Fatalf("ReconcileKeySet: %v", err)
	}
	if len(res.Adopted) != 1 || res.Adopted[0] != filepath.Join(dir, "kek.aws") {
		t.Fatalf("Adopted = %v, want just the new provider's blob", res.Adopted)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil || m.Files["kek.aws"].SHA256 != HashBytes([]byte("kms-wrapped-kek")) || m.Files["dek.key"].Operation != OpFirstBoot {
		t.Fatalf("manifest = %+v, %v; want the blob adopted and the rest untouched", m, err)
	}
}
