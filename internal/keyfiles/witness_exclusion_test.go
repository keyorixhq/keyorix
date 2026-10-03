package keyfiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/auditverify"
	"github.com/keyorixhq/keyorix/internal/config"
)

// maximalEncryptionConfig sets every path-bearing field Registry reads: salt,
// DEK (and their .pending siblings, created on disk below), a write-capable
// primary provider, every other write-capable type plus shamir as fallbacks,
// and the path-less/excluded types for good measure.
func maximalEncryptionConfig() *config.EncryptionConfig {
	return &config.EncryptionConfig{
		SaltPath: "kek.salt",
		DEKPath:  "dek.key",
		KeyProvider: config.KeyProviderConfig{
			Type:           "tpm",
			WrappedKeyPath: "kek.tpm",
			Fallbacks: []config.KeyProviderConfig{
				{Type: "aws-kms", WrappedKeyPath: "kek.aws"},
				{Type: "gcp-kms", WrappedKeyPath: "kek.gcp"},
				{Type: "azure-kms", WrappedKeyPath: "kek.azure"},
				{Type: "shamir", ShamirShareFiles: []string{"share1.hex", "share2.hex"}},
				{Type: "file", FilePath: "kek.file"},
				{Type: "password"},
				{Type: "env"},
				{Type: "exec"},
			},
		},
	}
}

// TestRegistry_NeverIncludesAuditHighWaterWitness guards the keyfiles half of
// INV-AUDITVERIFY-11: the audit high-water witness is a sibling of the
// database file and must never be enumerated as key material, because every
// Registry entry is bundled into `admin backup` archives and written back by
// `admin restore`. A witness restored from an old archive would compare the
// archive against its own old mark and prove nothing.
//
// The fixture is the worst realistic layout: the database, the witness, and
// every key file Registry can name all live in one directory, with the
// witness present on disk (so any directory scan or glob would find it).
//
// What this does not cover: a config that names the witness file directly as
// a key path (e.g. dek_path: .audit-highwater-witness). Registry follows
// config, so that misconfiguration would be enumerated; nothing here
// rejects it.
func TestRegistry_NeverIncludesAuditHighWaterWitness(t *testing.T) {
	dir := t.TempDir()
	enc := maximalEncryptionConfig()

	for _, name := range []string{
		"kek.salt", "dek.key", "kek.salt.pending", "dek.key.pending",
		"kek.tpm", "kek.aws", "kek.gcp", "kek.azure", "share1.hex", "share2.hex", "kek.file",
		"keyorix.db",
	} {
		writeFile(t, filepath.Join(dir, name))
	}
	witness := auditverify.WitnessPath(filepath.Join(dir, "keyorix.db"))
	if err := os.WriteFile(witness, []byte("witness"), 0600); err != nil {
		t.Fatalf("write witness: %v", err)
	}

	specs, err := Registry(enc, dir)
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	for _, s := range specs {
		if filepath.Clean(s.Path) == filepath.Clean(witness) ||
			filepath.Base(s.Path) == auditverify.AuditHighWaterWitnessFileName ||
			strings.Contains(filepath.Base(s.Path), "highwater-witness") {
			t.Fatalf("Registry enumerated the audit high-water witness %q as key material: %+v", witness, s)
		}
	}
	// Premise: the fixture really did drive every path-bearing branch, or the
	// absence check above is vacuous.
	if len(specs) != 10 {
		t.Fatalf("test bug: Registry returned %d entries, want 10 (salt, DEK, 2 pending, 4 wrapped KEKs, 2 shares): %+v", len(specs), specs)
	}
}
