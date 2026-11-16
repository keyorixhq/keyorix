package keyfiles

// #2424 / #2900 criterion 4: a set with no manifest (every install that
// predates it, on its first start after the upgrade) that also has a rotation
// staging file. Without a manifest nothing tells "rotate-kek stopped before it
// changed anything" from "rotate-kek stopped between its DEK and salt renames"
// (old salt + new DEK), so boot must not record the current files as
// generation 1 before they have been opened: in the second state that would
// make the fix (the staged salt renamed into place) look like a file from
// another generation at the next boot. The start still passes the boot
// refusal and says what to do, with the #4105 backup pointer for the salt.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReconcile_PreManifestSetWithRotationStaging_IsNotAdoptedBeforeItOpens(t *testing.T) {
	for _, staged := range []string{"kek.salt.pending", "dek.key.pending"} {
		t.Run(staged, func(t *testing.T) {
			dir := t.TempDir()
			enc := passwordSetConfig()
			writeSetWithoutManifest(t, dir, enc)
			stagedPath := filepath.Join(dir, staged)
			if err := os.WriteFile(stagedPath, []byte("staged by an interrupted rotation"), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := VerifyKeySetConsistency(enc, dir); err != nil {
				t.Fatalf("a complete pre-manifest set with a staging file must pass the boot refusal: %v", err)
			}
			res, err := ReconcileKeySet(enc, dir, ManifestFS{})
			if err != nil {
				t.Fatalf("ReconcileKeySet: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, ManifestFileName)); !os.IsNotExist(err) {
				t.Fatalf("a manifest was written over a set whose coherence an interrupted rotation leaves open (stat: %v)", err)
			}
			if len(res.Adopted) != 0 {
				t.Fatalf("adopted %v before the set was opened", res.Adopted)
			}
			warn := strings.Join(res.Warnings, "\n")
			for _, want := range []string{stagedPath, "key-rotation-runbook.md", "never delete a DEK's .pending file by hand"} {
				if !strings.Contains(warn, want) {
					t.Errorf("warnings %q do not contain %q", warn, want)
				}
			}
			if wantBackup := staged == "kek.salt.pending"; strings.Contains(warn, "`admin backup` refuses") != wantBackup {
				t.Errorf("the #4105 backup pointer must appear exactly for the salt staging file; warnings: %q", warn)
			}
			if _, err := os.Stat(stagedPath); err != nil {
				t.Errorf("boot must keep the staging file: %v", err)
			}
		})
	}
}
