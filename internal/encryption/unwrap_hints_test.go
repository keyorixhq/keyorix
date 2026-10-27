package encryption

// REVIEW-ENCRYPTIONOPS-1 R3/R4: when the DEK does not unwrap, Initialize names
// what an interrupted rotate-kek (<salt_path>.pending) or migrate-provider (the
// newest <dek_path>.migrate-backup.*) left, with the runbook's recovery. Only the
// message changes: the same calls succeed and fail as before.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	hintOldPass = "old-passphrase-for-hint-tests-0123"
	hintNewPass = "new-passphrase-for-hint-tests-4567"
)

func seedKeyManager(t *testing.T, dir string) {
	t.Helper()
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(hintOldPass); err != nil {
		t.Fatalf("seed Initialize: %v", err)
	}
	km.Wipe()
}

func initializeErr(dir, passphrase string) error {
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	defer km.Wipe()
	return km.Initialize(passphrase)
}

// rotate-kek killed after the DEK rename, before the salt rename: dek.key is under
// the new passphrase and the new salt, kek.salt is the old one. Neither passphrase
// unwraps it; the error names kek.salt.pending and the mv that recovers.
func TestInitialize_UnwrapFailureNamesThePendingSaltOfAnInterruptedRotateKEK(t *testing.T) {
	dir := t.TempDir()
	seedKeyManager(t, dir)
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(hintOldPass); err != nil {
		t.Fatal(err)
	}
	runRotationWithCrash(km, hintOldPass, hintNewPass, "kek:after-rename-dek")
	km.Wipe()

	pendingSalt := filepath.Join(dir, "kek.salt.pending")
	salt := filepath.Join(dir, "kek.salt")
	for _, pass := range []string{hintOldPass, hintNewPass} {
		err := initializeErr(dir, pass)
		if err == nil {
			t.Fatal("the interrupted rotation's DEK unwrapped: the precondition of this test does not hold")
		}
		msg := err.Error()
		for _, want := range []string{
			"failed to unwrap DEK — wrong passphrase or corrupted key file",
			pendingSalt + " exists: a rotate-kek was interrupted",
			"`mv " + pendingSalt + " " + salt + "`",
			"start with the NEW passphrase",
			`key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider"`,
		} {
			if !strings.Contains(msg, want) {
				t.Errorf("unwrap error lacks %q:\n%s", want, msg)
			}
		}
	}

	// The named command is the recovery: after it, the new passphrase opens the DEK.
	if err := os.Rename(pendingSalt, salt); err != nil {
		t.Fatal(err)
	}
	if err := initializeErr(dir, hintNewPass); err != nil {
		t.Fatalf("the recovery the error names did not work: %v", err)
	}
}

// rotate-kek killed before it touched dek.key: both pending files exist and
// dek.key is still under the old passphrase. The old passphrase keeps working
// (unchanged); a wrong one gets a hint that says NOT to rename them.
func TestInitialize_UnwrapFailureBeforeTheDEKRenameSaysNotToRename(t *testing.T) {
	dir := t.TempDir()
	seedKeyManager(t, dir)
	km := NewKeyManager(dir, "dek.key", "kek.salt")
	if err := km.Initialize(hintOldPass); err != nil {
		t.Fatal(err)
	}
	runRotationWithCrash(km, hintOldPass, hintNewPass, "kek:after-write-dek-pending")
	km.Wipe()

	if err := initializeErr(dir, hintOldPass); err != nil {
		t.Fatalf("the old passphrase must still open a DEK the rotation never replaced: %v", err)
	}
	err := initializeErr(dir, hintNewPass)
	if err == nil {
		t.Fatal("the new passphrase opened a DEK the rotation never replaced")
	}
	msg := err.Error()
	if !strings.Contains(msg, "interrupted before it replaced") || !strings.Contains(msg, "Do not rename them") {
		t.Fatalf("expected the do-not-rename hint, got:\n%s", msg)
	}
	if strings.Contains(msg, "`mv ") {
		t.Fatalf("the hint must not suggest renaming the salt while dek.key is still the old one:\n%s", msg)
	}
}

// migrate-provider killed after the re-wrap (or finished with the config not
// updated): dek.key is under the target provider. The error names the newest
// migrate-backup (not an older one, not a .restoring staging copy) and the way
// back; the target provider, as the hint says, opens it.
func TestInitialize_UnwrapFailureNamesTheNewestMigrateBackup(t *testing.T) {
	dir := t.TempDir()
	src := NewKeyManager(dir, "dek.key", "kek.salt")
	src.SetKeyProvider(fastPasswordProvider(hintOldPass, dir, "kek.salt"))
	if err := src.Initialize(hintOldPass); err != nil {
		t.Fatal(err)
	}
	wrapped, err := os.ReadFile(filepath.Join(dir, "dek.key")) // #nosec G304 -- t.TempDir() path
	if err != nil {
		t.Fatal(err)
	}
	older := filepath.Join(dir, "dek.key.migrate-backup.1600000000000000000-aaaaaaaa")
	newest := filepath.Join(dir, "dek.key.migrate-backup.1700000000000000000-bbbbbbbb")
	for _, p := range []string{older, newest, newest + ".restoring"} {
		if err := os.WriteFile(p, wrapped, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	if err := os.Chtimes(older, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(newest, now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := src.RewrapDEK(fastPasswordProvider(hintNewPass, dir, "target.salt")); err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	src.Wipe()

	km := NewKeyManager(dir, "dek.key", "kek.salt")
	km.SetKeyProvider(fastPasswordProvider(hintOldPass, dir, "kek.salt"))
	err = km.Initialize(hintOldPass)
	if err == nil {
		t.Fatal("the source provider opened a DEK re-wrapped under the target: the precondition of this test does not hold")
	}
	msg := err.Error()
	for _, want := range []string{
		newest + " is the newest migrate-provider backup",
		"Set storage.encryption.key_provider to the provider you migrated to",
		"`keyorix-server admin encryption migrate-provider --to-type <previous provider> --confirm`",
		`key-rotation-runbook.md, "Interrupted rotate-kek or migrate-provider"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("unwrap error lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, older) || strings.Contains(msg, ".restoring") {
		t.Errorf("the hint must name only the newest backup:\n%s", msg)
	}

	tgt := NewKeyManager(dir, "dek.key", "target.salt")
	tgt.SetKeyProvider(fastPasswordProvider(hintNewPass, dir, "target.salt"))
	if err := tgt.Initialize(hintNewPass); err != nil {
		t.Fatalf("the target provider the hint points at did not open the DEK: %v", err)
	}
	tgt.Wipe()
}

// Without leftovers the error is exactly what it was, and a correct passphrase
// still opens the DEK even with leftovers beside it.
func TestInitialize_UnwrapFailureWithoutLeftoversIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	seedKeyManager(t, dir)
	err := initializeErr(dir, "not-the-passphrase-at-all-000000")
	if err == nil {
		t.Fatal("a wrong passphrase opened the DEK")
	}
	if !strings.Contains(err.Error(), "failed to unwrap DEK — wrong passphrase or corrupted key file") || strings.Contains(err.Error(), "\n  - ") {
		t.Fatalf("error without leftovers changed: %q", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "dek.key.migrate-backup.1-x"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := initializeErr(dir, hintOldPass); err != nil {
		t.Fatalf("a leftover backup changed what Initialize accepts: %v", err)
	}
}
