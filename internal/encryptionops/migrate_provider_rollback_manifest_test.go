package encryptionops

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
	"github.com/keyorixhq/keyorix/internal/securefiles"
)

// rollbackFixture is a key directory right after migrate-provider's re-wrap
// committed the re-wrapped DEK to the key-set manifest, with the previous
// wrapped DEK kept as backup.bin for RestoreBackup.
func rollbackFixture(t *testing.T) (dir string, enc *config.EncryptionConfig, ks *keyfiles.SetWriter) {
	t.Helper()
	dir = chdirTemp(t)
	enc = &config.EncryptionConfig{DEKPath: "active.bin", SaltPath: "salt.bin"}
	for name, data := range map[string]string{
		"backup.bin": "original-wrapped-dek-bytes-0123456789",
		"active.bin": "re-wrapped-bytes",
		"salt.bin":   "salt-0123456789abcdef0123456789ab",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ks, err := keyfiles.NewSetWriter(enc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := ks.CommitManifestFromDisk(keyfiles.OpRewrapDEK, ks.Required()...); err != nil {
		t.Fatal(err)
	}
	return dir, enc, ks
}

// failingManifestWrites fails every manifest write after the first ok ones.
func failingManifestWrites(ok int) keyfiles.ManifestFS {
	n := 0
	return keyfiles.ManifestFS{WriteSync: func(dir, name string, data []byte) error {
		if n++; n <= ok {
			return securefiles.SecureWriteFileSync(dir, name, data, 0o600)
		}
		return errors.New("injected manifest write failure")
	}}
}

// REVIEW-3714-DEEP-1 finding 2: when neither the stage nor the commit reached
// the manifest, it still records the re-wrapped DEK and the next start refuses
// the restored one. The message must say so and name the manifest, not claim
// the next start records the rollback.
func TestRestoreBackup_StageAndCommitFail_MessageSaysNextStartRefuses(t *testing.T) {
	dir, enc, ks := rollbackFixture(t)

	out, _ := captureStderr(t, func() error {
		RestoreBackup(dir, "backup.bin", "active.bin", ks.WithFS(failingManifestWrites(0)))
		return nil
	})

	if got := string(readOrFatal(t, filepath.Join(dir, "active.bin"))); got != "original-wrapped-dek-bytes-0123456789" {
		t.Fatalf("the backup must still be restored, active DEK = %q", got)
	}
	if strings.Contains(out, "records it") {
		t.Errorf("nothing was staged, so the message must not promise the next start records the rollback:\n%s", out)
	}
	if !strings.Contains(out, "refuses") || !strings.Contains(out, ks.Path()) {
		t.Errorf("the message must say the next start refuses and name the manifest %s:\n%s", ks.Path(), out)
	}
	// The claim the message makes is true.
	if err := keyfiles.VerifyKeySetConsistency(enc, dir); err == nil || !strings.Contains(err.Error(), "does not match the key-set manifest") {
		t.Fatalf("boot after an unrecorded rollback: got %v, want a manifest mismatch refusal", err)
	}
}

// The other branch: the stage reached the manifest and only the commit failed.
// Boot finds the staged rollback completed and records it, as the message says.
func TestRestoreBackup_OnlyCommitFails_MessageSaysNextStartRecords(t *testing.T) {
	dir, enc, ks := rollbackFixture(t)

	out, _ := captureStderr(t, func() error {
		RestoreBackup(dir, "backup.bin", "active.bin", ks.WithFS(failingManifestWrites(1)))
		return nil
	})

	if !strings.Contains(out, "next server start records it") {
		t.Errorf("a staged rollback is recorded at the next start; the message must say so:\n%s", out)
	}
	if err := keyfiles.VerifyKeySetConsistency(enc, dir); err != nil {
		t.Fatalf("boot after a staged rollback whose commit failed must pass: %v", err)
	}
}

func readOrFatal(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
