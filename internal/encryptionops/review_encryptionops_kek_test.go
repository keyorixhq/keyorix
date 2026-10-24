// review_encryptionops_kek_test.go — REVIEW-ENCRYPTIONOPS-1 findings on rotate-kek.
//
// F3: rotate-kek is the response to a leaked master passphrase, but it left every
// <dek_path>.migrate-backup.* file in place without a word. Such a backup is the
// DEK wrapped under an older KEK, so the old passphrase plus that file still
// unwraps the live DEK after the rotation.
//
// F4: rotate-kek only works for the password provider. With any other provider it
// opened the database and the key files and then failed with an error that named
// neither the provider nor migrate-provider.
package encryptionops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotateKEKWithConfig_NamesLeftoverMigrateBackups(t *testing.T) {
	chdirTemp(t)
	cfg, _, _ := kekFixture(t)
	closeTestDB(migrateEncOpsTables(t, testDBFile))

	// What a successful migrate-provider leaves behind: the previous wrapped DEK.
	wrapped, err := os.ReadFile("dek.key")
	if err != nil {
		t.Fatalf("read dek.key: %v", err)
	}
	backup := "dek.key.migrate-backup.1700000000"
	if err := os.WriteFile(backup, wrapped, 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}

	setNewPassphraseEnv(t, testNewPassphrase)
	out, err := captureOutput(t, func() error {
		return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	})
	if err != nil {
		t.Fatalf("RotateKEKWithConfig: %v", err)
	}
	if !strings.Contains(out, backup) {
		t.Fatalf("rotate-kek must name the leftover backup %s (the OLD passphrase still unwraps the DEK from it); output:\n%s", backup, out)
	}
	if !strings.Contains(out, "migrate-provider cleanup") {
		t.Fatalf("rotate-kek must point at `migrate-provider cleanup`; output:\n%s", out)
	}
}

func TestRotateKEKWithConfig_NonPasswordProviderRefusedUpFront(t *testing.T) {
	dir := chdirTemp(t)
	cfg := testConfig(true)
	cfg.Storage.Encryption.KeyProvider.Type = "file"
	cfg.Storage.Encryption.KeyProvider.FilePath = filepath.Join(dir, "kek.bin")
	setPassphraseEnv(t, testBaselinePassphrase)
	setNewPassphraseEnv(t, testNewPassphrase)

	err := RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc())
	if err == nil {
		t.Fatal("rotate-kek must refuse a non-password key provider")
	}
	if !strings.Contains(err.Error(), "migrate-provider") || !strings.Contains(err.Error(), `"file"`) {
		t.Fatalf("expected a refusal naming the provider and migrate-provider, got: %v", err)
	}
	if _, serr := os.Stat(testDBFile); !os.IsNotExist(serr) {
		t.Fatalf("rotate-kek opened/created the database before refusing (stat err=%v)", serr)
	}
}
