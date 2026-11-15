package keyfiles

// AdoptProvenKeySet: the adoption ReconcileKeySet defers for a manifest-less
// set with staging files, run once the set has been opened.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdoptProvenKeySet_DeferredSet_AdoptsActiveFilesOnly(t *testing.T) {
	dir := t.TempDir()
	enc := passwordSetConfig()
	writeSetWithoutManifest(t, dir, enc)
	staged := filepath.Join(dir, "kek.salt.pending")
	if err := os.WriteFile(staged, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil || !res.AdoptionDeferred {
		t.Fatalf("ReconcileKeySet = %+v, %v; want the adoption deferred", res, err)
	}

	res, err = AdoptProvenKeySet(enc, dir, ManifestFS{})
	if err != nil {
		t.Fatalf("AdoptProvenKeySet: %v", err)
	}
	if len(res.Adopted) != 2 || !strings.Contains(res.AdoptReason, "kek.salt.pending") {
		t.Fatalf("result = %+v, want the salt and DEK adopted, the staging file named as left out", res)
	}
	m, err := LoadManifest(filepath.Join(dir, ManifestFileName))
	if err != nil || m.Generation != 1 || len(m.Files) != 2 {
		t.Fatalf("manifest = %+v, %v; want generation 1 with the two active files", m, err)
	}
	if _, ok := m.Files["kek.salt.pending"]; ok {
		t.Fatal("a staging file must never be recorded as part of the set")
	}

	// From now on the set is checked like any other: a later start does not
	// adopt again, and the leftover staging file no longer defers anything.
	again, err := ReconcileKeySet(enc, dir, ManifestFS{})
	if err != nil || again.AdoptionDeferred || len(again.Adopted) != 0 {
		t.Fatalf("next start = %+v, %v; want nothing adopted or deferred", again, err)
	}
}

// Nothing to adopt: a set that has a manifest, and a fresh directory.
func TestAdoptProvenKeySet_ManifestPresentOrFresh_NoOp(t *testing.T) {
	enc := passwordSetConfig()
	withManifest := t.TempDir()
	provisionGeneration(t, withManifest, enc)
	before, err := os.ReadFile(filepath.Join(withManifest, ManifestFileName))
	if err != nil {
		t.Fatal(err)
	}
	for name, dir := range map[string]string{"manifest present": withManifest, "fresh": t.TempDir()} {
		res, err := AdoptProvenKeySet(enc, dir, ManifestFS{})
		if err != nil || len(res.Adopted) != 0 {
			t.Fatalf("%s: AdoptProvenKeySet = %+v, %v; want a no-op", name, res, err)
		}
	}
	after, err := os.ReadFile(filepath.Join(withManifest, ManifestFileName))
	if err != nil || string(after) != string(before) {
		t.Fatalf("the existing manifest changed (%v)", err)
	}
}
