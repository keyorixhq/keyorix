package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The multi-replica rotation procedure (docs/operator/j6-key-rotation.md
// "Several server replicas", step 4; key-rotation-runbook.md §3; ADR-039):
// rotate the DEK on host A, copy the new key files to replica B, start B.
// B already has its own manifest recording the old DEK (first boot or
// adoption), so the copy must carry A's manifest with dek.key and kek.salt.
// This pins both halves: the documented copy (key files plus manifest) boots,
// and the copy the docs used to describe (key files only) is refused, which is
// why the manifest is part of the step.
func TestVerifyKeySetConsistency_RotateOnOneReplica_CopyKeyFilesWithManifest_Passes(t *testing.T) {
	enc := passwordSetConfig()
	hostA, hostB := t.TempDir(), t.TempDir()
	provisionGeneration(t, hostA, enc)
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		cpFile(t, filepath.Join(hostA, n), filepath.Join(hostB, n))
	}
	if err := VerifyKeySetConsistency(enc, hostB); err != nil {
		t.Fatalf("replica B before the rotation: %v", err)
	}

	// rotate-dek on host A, through the SetWriter as the admin command does.
	ks, err := NewSetWriter(enc, hostA)
	if err != nil {
		t.Fatal(err)
	}
	dekA := filepath.Join(hostA, "dek.key")
	files := map[string][]byte{dekA: []byte("rotated-dek-on-host-a")}
	if err := ks.StageManifest(OpRotateDEK, files); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dekA, files[dekA], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ks.CommitManifest(OpRotateDEK, files); err != nil {
		t.Fatal(err)
	}

	// Key files only: B's own manifest still records the old DEK.
	onlyKeys := t.TempDir()
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		cpFile(t, filepath.Join(hostB, n), filepath.Join(onlyKeys, n))
	}
	for _, n := range []string{"kek.salt", "dek.key"} {
		cpFile(t, filepath.Join(hostA, n), filepath.Join(onlyKeys, n))
	}
	err = VerifyKeySetConsistency(enc, onlyKeys)
	if err == nil || !strings.Contains(err.Error(), "does not match the key-set manifest") {
		t.Fatalf("dek.key and kek.salt copied without the manifest must be refused, got %v", err)
	}

	// The documented step: dek.key, kek.salt and keyset.manifest.json.
	for _, n := range []string{"kek.salt", "dek.key", ManifestFileName} {
		cpFile(t, filepath.Join(hostA, n), filepath.Join(hostB, n))
	}
	if err := VerifyKeySetConsistency(enc, hostB); err != nil {
		t.Fatalf("replica B with dek.key, kek.salt and the manifest copied from the rotating host must boot: %v", err)
	}
}
