package encryption

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
	"github.com/keyorixhq/keyorix/internal/keyfiles"
)

// Behavioural half of #2900 criterion 6 (the structural half is
// internal/keyfiles' TestEveryKeyMaterialWriterUpdatesTheManifest): after each
// writer, the manifest records exactly what is on disk.

func passwordEncConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{
		Enabled:     true,
		DEKPath:     "keys/dek.key",
		SaltPath:    "keys/kek.salt",
		KeyProvider: config.KeyProviderConfig{Type: "password"},
	}
}

// assertManifestMatchesDisk fails unless every named file (relative to dir)
// has a manifest entry whose hash is the file's current hash, written by op,
// and no operation is left staged.
func assertManifestMatchesDisk(t *testing.T, manifestPath, dir, op string, rels ...string) *keyfiles.Manifest {
	t.Helper()
	m, err := keyfiles.LoadManifest(manifestPath)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if m.Next != nil {
		t.Errorf("manifest still has a staged %q operation after the writer returned", m.Next.Operation)
	}
	mdir := filepath.Dir(manifestPath)
	for _, rel := range rels {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		key, err := filepath.Rel(mdir, filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		e, ok := m.Files[filepath.ToSlash(key)]
		if !ok {
			t.Errorf("manifest has no entry for %s (entries: %v)", key, m.Files)
			continue
		}
		if e.SHA256 != keyfiles.HashBytes(data) {
			t.Errorf("manifest hash for %s does not match the file on disk", key)
		}
		if op != "" && e.Operation != op {
			t.Errorf("manifest entry for %s was written by %q, want %q", key, e.Operation, op)
		}
	}
	return m
}

func newPasswordService(t *testing.T, dir, pass string) *Service {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	svc := NewService(passwordEncConfig(), dir)
	if err := svc.Initialize(pass); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	t.Cleanup(svc.Shutdown)
	return svc
}

func TestFirstBoot_ManifestRecordsTheSet(t *testing.T) {
	dir := t.TempDir()
	newPasswordService(t, dir, "first-boot-pass")
	m := assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		keyfiles.OpFirstBoot, "keys/kek.salt", "keys/dek.key")
	if m.Generation != 1 {
		t.Errorf("first boot generation = %d, want 1", m.Generation)
	}
}

// A first boot with a KEK provider's own files in the set: the files the
// provider wrote before the DEK existed are recorded by the same first-boot
// commit. A Shamir fallback's shares are the provider files a test can create
// without a KMS or TPM.
func TestFirstBoot_ManifestRecordsProviderFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "keys"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"share-1.hex", "share-2.hex"} {
		if err := os.WriteFile(filepath.Join(dir, "keys", s), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := passwordEncConfig()
	cfg.KeyProvider.Fallbacks = []config.KeyProviderConfig{{Type: "shamir", ShamirShareFiles: []string{"keys/share-1.hex", "keys/share-2.hex"}}}
	km := NewService(cfg, dir).keyManager
	km.SetKeyProvider(crypto.NewPasswordKeyProvider("p", dir, "keys/kek.salt"))
	if err := km.Initialize("p"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		keyfiles.OpFirstBoot, "keys/kek.salt", "keys/dek.key", "keys/share-1.hex", "keys/share-2.hex")
}

func TestRotateKEK_ManifestRecordsNewSaltAndDEK(t *testing.T) {
	dir := t.TempDir()
	svc := newPasswordService(t, dir, "old-pass")
	if err := svc.keyManager.RotateKEKPassphrase("old-pass", "new-pass"); err != nil {
		t.Fatalf("RotateKEKPassphrase: %v", err)
	}
	m := assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		keyfiles.OpRotateKEK, "keys/kek.salt", "keys/dek.key")
	if m.Generation != 2 || m.Files["dek.key"].Generation != 2 || m.Files["kek.salt"].Generation != 2 {
		t.Errorf("after one rotate-kek: set generation %d, dek %d, salt %d; want 2, 2, 2",
			m.Generation, m.Files["dek.key"].Generation, m.Files["kek.salt"].Generation)
	}
}

func TestRotateDEKWithSweep_ManifestRecordsNewDEKOnly(t *testing.T) {
	dir := t.TempDir()
	svc := newPasswordService(t, dir, "pass")
	if err := svc.keyManager.RotateDEKWithSweep("pass", func(_, _ *EncryptionService, _ string) error { return nil }); err != nil {
		t.Fatalf("RotateDEKWithSweep: %v", err)
	}
	m := assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		"", "keys/kek.salt", "keys/dek.key")
	if m.Files["dek.key"].Operation != keyfiles.OpRotateDEK || m.Files["dek.key"].Generation != 2 {
		t.Errorf("dek entry = %+v, want rotate-dek at generation 2", m.Files["dek.key"])
	}
	if m.Files["kek.salt"].Operation != keyfiles.OpFirstBoot || m.Files["kek.salt"].Generation != 1 {
		t.Errorf("salt entry = %+v, want untouched first-boot generation 1 (the DEK rotates independently)", m.Files["kek.salt"])
	}
}

// PromotePendingDEK (crash recovery of a committed sweep) replaces the active
// DEK too, possibly with a file the crashed sweep never staged.
func TestPromotePendingDEK_ManifestRecordsPromotedDEK(t *testing.T) {
	dir := t.TempDir()
	svc := newPasswordService(t, dir, "pass")
	pending := []byte("a-new-wrapped-dek-from-a-crashed-sweep")
	if err := os.WriteFile(filepath.Join(dir, "keys", "dek.key.pending"), pending, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := svc.keyManager.PromotePendingDEK(); err != nil {
		t.Fatalf("PromotePendingDEK: %v", err)
	}
	assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		keyfiles.OpRotateDEK, "keys/dek.key")
}

func TestRewrapDEK_ManifestRecordsNewDEK(t *testing.T) {
	dir := t.TempDir()
	svc := newPasswordService(t, dir, "pass")
	newProvider := crypto.NewPasswordKeyProvider("other-pass", dir, "keys/kek2.salt")
	if err := svc.keyManager.RewrapDEK(newProvider); err != nil {
		t.Fatalf("RewrapDEK: %v", err)
	}
	assertManifestMatchesDisk(t, filepath.Join(dir, "keys", keyfiles.ManifestFileName), dir,
		keyfiles.OpRewrapDEK, "keys/dek.key")
}

// A writer on an install that predates the manifest records the whole current
// set first, so the files it did not touch are not left unrecorded.
func TestWriterOnPreManifestInstall_AdoptsTheRestOfTheSet(t *testing.T) {
	dir := t.TempDir()
	svc := newPasswordService(t, dir, "pass")
	manifest := filepath.Join(dir, "keys", keyfiles.ManifestFileName)
	if err := os.Remove(manifest); err != nil {
		t.Fatal(err)
	}
	if err := svc.keyManager.RotateDEKWithSweep("pass", func(_, _ *EncryptionService, _ string) error { return nil }); err != nil {
		t.Fatalf("RotateDEKWithSweep: %v", err)
	}
	m := assertManifestMatchesDisk(t, manifest, dir, "", "keys/kek.salt", "keys/dek.key")
	if m.Files["kek.salt"].Operation != keyfiles.OpAdopted {
		t.Errorf("salt entry = %+v, want adopted", m.Files["kek.salt"])
	}
}
