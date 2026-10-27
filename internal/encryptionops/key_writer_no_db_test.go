package encryptionops

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/keyorixhq/keyorix/internal/config"
	"github.com/keyorixhq/keyorix/internal/crypto"
)

// KEYMATERIAL-TAILS-1 item 5 (ATOMIC-OWED-1 leftover, the #3523 family): the key
// writers (openKeyWriter) refuse missing keys BEFORE they open the database.
// Opening a SQLite path creates the file, so a run from the wrong directory or
// with a wrong dek_path left a fresh empty database behind next to the refusal;
// the next server start from that directory then found "its" database.
func TestKeyWriters_MissingKeys_CreateNoDatabase(t *testing.T) {
	keyFile := filepath.Join(t.TempDir(), "raw.key")
	if err := os.WriteFile(keyFile, []byte(hex.EncodeToString(bytes.Repeat([]byte{9}, crypto.KEKSize))), 0o600); err != nil {
		t.Fatal(err)
	}
	ops := []struct {
		name string
		run  func(cfg *config.Config) error
	}{
		{"rotate", func(cfg *config.Config) error { return RotateWithConfig(cfg, true, false, zeroPassSrc()) }},
		{"upgrade-aad", func(cfg *config.Config) error { return UpgradeAADWithConfig(cfg, zeroPassSrc()) }},
		{"rotate-kek", func(cfg *config.Config) error { return RotateKEKWithConfig(cfg, true, zeroPassSrc(), zeroPassSrc()) }},
		{"migrate-provider", func(cfg *config.Config) error {
			return MigrateProviderWithConfig(cfg, MigrateOpts{ToType: "file", ToFilePath: keyFile}, true, zeroPassSrc(), zeroPassSrc())
		}},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			dir := chdirTemp(t)
			setPassphraseEnv(t, testBaselinePassphrase)
			setNewPassphraseEnv(t, testNewPassphrase)
			cfg := testConfig(true)
			out, err := captureOutput(t, func() error { return op.run(cfg) })
			if err == nil {
				t.Fatalf("%s with no key files succeeded; output:\n%s", op.name, out)
			}
			if !strings.Contains(err.Error(), "does not create keys") {
				t.Errorf("%s: refusal %q is not the missing-keys one", op.name, err)
			}
			for _, f := range []string{testDBFile, testDBFile + "-wal", testDBFile + "-shm", "dek.key", "kek.salt"} {
				if _, serr := os.Stat(filepath.Join(dir, f)); serr == nil {
					t.Errorf("%s refused for missing keys but left %s behind", op.name, f)
				}
			}
		})
	}
}
